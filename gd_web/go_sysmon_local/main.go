package main

import (
	"archive/zip"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	_ "modernc.org/sqlite" // 纯 Go 版本 SQLite，跨平台免 CGO 编译
)

//go:embed bin/Sysmon64.exe
var sysmonAssets embed.FS

var (
	isInstalled          int32 = 0
	originalSysmonExists bool
	lastLogTime          = time.Now().UTC().AddDate(0, 0, -7) // 默认拉取最近7天数据

	modadvapi32     = syscall.NewLazyDLL("advapi32.dll")
	procCheckToken  = modadvapi32.NewProc("CheckTokenMembership")
	modkernel32     = syscall.NewLazyDLL("kernel32.dll")
	procSetFileAttr = modkernel32.NewProc("SetFileAttributesW")
)

// ---------------------------------------------------------
// 辅助与提权模块
// ---------------------------------------------------------
func cleanUTF16(b []byte) string {
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", ""))
}

func getAgentDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}

func isAdmin() bool {
	sid, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return false
	}
	var isMember int32
	ret, _, _ := procCheckToken.Call(0, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&isMember)))
	return ret != 0 && isMember != 0
}

func runElevated() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, windows.SW_SHOWNORMAL)
}

// ---------------------------------------------------------
// OPSEC：文件隐身与反隐身机制 (方便取证拷贝)
// ---------------------------------------------------------
func hideFile(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err == nil {
		// 赋予隐藏 (0x02) 与 系统级文件 (0x04) 属性，防止被黑客一键清空
		procSetFileAttr.Call(uintptr(unsafe.Pointer(ptr)), uintptr(0x02|0x04))
	}
}

func unhideFile(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err == nil {
		// 恢复为正常文件 (0x80)，方便防守方直接鼠标拷贝带走
		procSetFileAttr.Call(uintptr(unsafe.Pointer(ptr)), uintptr(0x80))
	}
}

// ---------------------------------------------------------
// 工具方法：完美目录 ZIP 打包压缩
// ---------------------------------------------------------
func zipDirectory(sourceDir, targetZip string) error {
	zipFile, err := os.Create(targetZip)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(sourceDir, path)
		header.Name = filepath.ToSlash(relPath)
		header.Method = zip.Deflate

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})
	return nil
}

// ---------------------------------------------------------
// 核心模块一：高级应急响应快照提取 (修正引号吞噬 BUG)
// ---------------------------------------------------------
func performIRSnapshot() {
	fmt.Println("\n[*] 开始执行系统基线与 APT 级现场快照采集 (证据固化)...")
	timestamp := time.Now().Format("20060102_150405")
	baseName := "IR_Report_" + timestamp
	dumpDir := filepath.Join(getAgentDir(), baseName)
	_ = os.MkdirAll(dumpDir, 0755)

	// 使用结构体数组分离 exe 和 args，彻底避开 cmd 的引号解析 BUG
	tasks := []struct {
		name     string
		filename string
		exe      string
		args     []string
	}{
		// 常规信息提取
		{"系统与基线信息", "01_system_info.txt", "cmd", []string{"/c", "chcp 65001 >nul && systeminfo"}},
		{"网络会话与端口", "02_network_sessions.txt", "cmd", []string{"/c", "chcp 65001 >nul && netstat -anob"}},
		{"DNS 解析缓存(查C2)", "03_dns_cache.txt", "cmd", []string{"/c", "chcp 65001 >nul && ipconfig /displaydns"}},
		{"运行中进程列表", "04_processes.txt", "cmd", []string{"/c", "chcp 65001 >nul && tasklist /v"}},
		{"近期程序执行历史(Prefetch)", "05_prefetch_list.txt", "cmd", []string{"/c", "dir /a /t:c /o:-d C:\\Windows\\Prefetch"}},
		{"WMI无文件隐蔽订阅", "06_wmi_persistence.txt", "powershell", []string{"-NoProfile", "-Command", "chcp 65001 >$null; Get-WmiObject -Namespace root\\subscription -Class __EventFilter"}},
		{"常规计划任务列表", "07_scheduled_tasks.txt", "cmd", []string{"/c", "chcp 65001 >nul && schtasks /query /fo LIST /v"}},
		{"BITS后台传输任务", "08_bits_jobs.txt", "cmd", []string{"/c", "chcp 65001 >nul && bitsadmin /list /allusers /verbose"}},

		// 修复并增强的注册表项 (直接调用 reg.exe，彻底避开路径空格引发的语法错误)
		{"底层幽灵计划任务缓存", "09_taskcache_registry.txt", "reg", []string{"query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`, "/s"}},
		{"IFEO映像劫持后门", "10_ifeo_hijack.txt", "reg", []string{"query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, "/s"}},
		{"深层高危注册表(Run键)", "11_registry_run.txt", "reg", []string{"query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "/s"}},
		
		// 新增：法庭级/APT级的程序执行痕迹挖掘 (即使文件被删，依然留痕)
		{"内核级运行留痕(BAM)", "12_bam_execution.txt", "reg", []string{"query", `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`, "/s"}},
		{"系统程序运行痕迹(ShimCache)", "13_shimcache.txt", "reg", []string{"query", `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, "/s"}},
		{"用户界面运行痕迹(UserAssist)", "14_userassist.txt", "reg", []string{"query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`, "/s"}},
	}

	for _, t := range tasks {
		fmt.Printf("  -> 正在提取证据: %s\n", t.name)
		cmd := exec.Command(t.exe, t.args...)
		out, _ := cmd.CombinedOutput()
		_ = os.WriteFile(filepath.Join(dumpDir, t.filename), out, 0644)
	}

	fmt.Println("  -> 正在打包 Windows 核心底层日志 (EVTX格式，包含代码明文与行为轨迹)...")
	evtxLogs := map[string]string{
		"Security": "EventLog_01_Security.evtx",
		"System":   "EventLog_02_System.evtx",
		"Microsoft-Windows-PowerShell/Operational":                           "EventLog_03_PowerShell_Op.evtx",
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "EventLog_04_RDP_Logons.evtx",
	}

	for channel, filename := range evtxLogs {
		exec.Command("wevtutil", "epl", channel, filepath.Join(dumpDir, filename)).Run()
	}

	err := exec.Command("wevtutil", "epl", "Microsoft-Windows-Sysmon/Operational", filepath.Join(dumpDir, "EventLog_06_Sysmon_History.evtx")).Run()
	if err == nil {
		fmt.Println("  -> 发现存量 Sysmon，历史记录已成功抢救备份！")
	}

	fmt.Println("  -> 正在对庞大的取证数据进行高强度 ZIP 归档...")
	zipPath := filepath.Join(getAgentDir(), baseName+".zip")
	if err := zipDirectory(dumpDir, zipPath); err == nil {
		os.RemoveAll(dumpDir)
		fmt.Printf("[+] 案发现场快照固化完毕！压缩包存放于: %s\n", zipPath)
	} else {
		fmt.Printf("[+] 现场快照打包失败，保留原文件于: %s\n", dumpDir)
	}
}

// ---------------------------------------------------------
// 核心模块二：底层探针的生命周期管理
// ---------------------------------------------------------
func isSysmonInstalled() bool {
	cmd := exec.Command("sc.exe", "query", "Sysmon64")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func installIRSysmon() {
	originalSysmonExists = isSysmonInstalled()
	confPath := filepath.Join(getAgentDir(), "ir_config.xml")

	irConfig := `<?xml version="1.0" encoding="utf-8"?>
<Sysmon schemaversion="4.91">
  <HashAlgorithms>MD5,SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="IR_Rules" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
      <NetworkConnect onmatch="exclude" />
      <ProcessTerminate onmatch="exclude" />
      <FileCreate onmatch="exclude" />
      <RegistryEvent onmatch="exclude" />
      <DnsQuery onmatch="exclude" />
    </RuleGroup>
  </EventFiltering>
</Sysmon>`

	_ = os.WriteFile(confPath, []byte(irConfig), 0644)
	defer os.Remove(confPath)

	sysmonPath := filepath.Join(getAgentDir(), "Sysmon64.exe")
	data, _ := sysmonAssets.ReadFile("bin/Sysmon64.exe")
	_ = os.WriteFile(sysmonPath, data, 0755)

	if !originalSysmonExists {
		fmt.Println("\n[*] 正在安装底层取证监控探针...")
		out, err := exec.Command(sysmonPath, "-accepteula", "-i", confPath).CombinedOutput()
		if err != nil {
			if strings.Contains(cleanUTF16(out), "already registered") {
				exec.Command(sysmonPath, "-u", "force").Run()
				time.Sleep(3 * time.Second)
				exec.Command(sysmonPath, "-accepteula", "-i", confPath).Run()
			}
		}
	} else {
		fmt.Println("\n[*] 探针已存在，正在热更新激进级取证策略...")
		if exec.Command("Sysmon64.exe", "-c", confPath).Run() != nil {
			exec.Command(sysmonPath, "-c", confPath).Run()
		}
	}
	atomic.StoreInt32(&isInstalled, 1)
	fmt.Println("[+] 探针监控设施就绪！")
}

// ---------------------------------------------------------
// 核心模块三：极致性能的 SQLite 实时事件窃听与落盘
// ---------------------------------------------------------
func initDB() *sql.DB {
	dbPath := filepath.Join(getAgentDir(), "trace_logs.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		panic("无法打开本地数据库: " + err.Error())
	}

	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA temp_store = MEMORY;",
		"PRAGMA cache_size = -64000;",
	}
	for _, p := range pragmas {
		db.Exec(p)
	}

	createTableSQL := `CREATE TABLE IF NOT EXISTS sysmon_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		time_created DATETIME,
		event_id TEXT,
		raw_xml TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_time ON sysmon_logs(time_created);
	CREATE INDEX IF NOT EXISTS idx_event ON sysmon_logs(event_id);`

	db.Exec(createTableSQL)

	// 对抗隐藏：运行期间变为系统级隐身文件
	hideFile(dbPath)
	hideFile(dbPath + "-wal")
	hideFile(dbPath + "-shm")

	fmt.Printf("[+] 事件落盘数据库已建立 (已启用运行期隐身防删保护)\n")
	return db
}

func collectLogsToSQLite(db *sql.DB) {
	fmt.Println("[*] 行为窃听引擎启动，实时捕捉黑客操作...")

	eventRe := regexp.MustCompile(`(?s)<Event\b.*?</Event>`)
	timeRe := regexp.MustCompile(`SystemTime=["']([^"']+)["']`)
	idRe := regexp.MustCompile(`<EventID>([0-9]+)</EventID>`)

	for {
		if atomic.LoadInt32(&isInstalled) == 0 {
			time.Sleep(2 * time.Second)
			continue
		}

		ts := lastLogTime.UTC().Format("2006-01-02T15:04:05.000Z")
		query := fmt.Sprintf(`*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=11 or EventID=12 or EventID=13 or EventID=22) and TimeCreated[@SystemTime>'%s']]]`, ts)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
			"/q:"+query, "/c:500", "/rd:false", "/e:root")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		out, err := cmd.CombinedOutput()
		cancel()

		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		events := eventRe.FindAllString(string(out), -1)
		if len(events) == 0 {
			fmt.Printf("\r[+] 静默窃听中... 暂无异常动作 (心跳时间: %s)      ", lastLogTime.Local().Format("15:04:05"))
			time.Sleep(5 * time.Second)
			continue
		}

		var maxTime time.Time
		tx, _ := db.Begin()
		stmt, _ := tx.Prepare("INSERT INTO sysmon_logs (time_created, event_id, raw_xml) VALUES (?, ?, ?)")

		for _, evtStr := range events {
			tmMatch := timeRe.FindStringSubmatch(evtStr)
			var parsedTime string
			if len(tmMatch) > 1 {
				if pt, err := time.Parse(time.RFC3339Nano, tmMatch[1]); err == nil {
					parsedTime = pt.Local().Format("2006-01-02 15:04:05")
					if pt.After(maxTime) {
						maxTime = pt
					}
				}
			}

			idMatch := idRe.FindStringSubmatch(evtStr)
			parsedID := "0"
			if len(idMatch) > 1 {
				parsedID = idMatch[1]
			}

			stmt.Exec(parsedTime, parsedID, evtStr)
		}

		stmt.Close()
		tx.Commit()

		if !maxTime.IsZero() {
			lastLogTime = maxTime
		}

		fmt.Printf("\r[*] 极速落盘: 成功捕获并封存 %d 条高危操作记录...     ", len(events))
	}
}

// ---------------------------------------------------------
// 主程序入口
// ---------------------------------------------------------
func main() {
	if !isAdmin() {
		fmt.Println("【系统提示】取证引擎需要最高管理员权限。正在申请...")
		runElevated()
		return
	}

	fmt.Println("=========================================================")
	fmt.Println("   Standalone IR & Threat Hunting Agent (单兵取证仪)  ")
	fmt.Println("=========================================================")

	// 1. 深度现场取证快照
	performIRSnapshot()

	// 2. 部署探针
	installIRSysmon()

	// 3. 初始化并隐藏数据库
	db := initDB()
	dbPath := filepath.Join(getAgentDir(), "trace_logs.db")
	defer db.Close()

	// 4. Ctrl+C 撤退信号拦截，解除隐身方便拷走
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n\n[*] 接收到退出信号，正在卸载驱动与清理环境...")
		sysmonPath := filepath.Join(getAgentDir(), "Sysmon64.exe")
		
		if !originalSysmonExists {
			cmd := exec.Command(sysmonPath, "-u", "force")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Run()
		}
		os.Remove(sysmonPath)
		
		// 退出时解除数据库的系统级隐身属性，方便排查人员用 U 盘直观拷走
		unhideFile(dbPath)
		unhideFile(dbPath + "-wal")
		unhideFile(dbPath + "-shm")
		fmt.Println("[+] 退场隐身保护已解除，您可以直接拷贝 trace_logs.db 进行分析。")
		os.Exit(0)
	}()

	// 5. 挂起主线程持续监听
	collectLogsToSQLite(db)
}