package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)
// 1. 在全局变量区增加 Token 和 书签文件路径
const AgentToken = "Sysmon-EDR-Super-Secret-Token-2026" // 请与后端保持一致
var bookmarkFile = filepath.Join(getAgentDir(), "bookmark.dat")
//go:embed bin/Sysmon64.exe
var sysmonAssets embed.FS

// --- 全局配置区域 ---
const ServerURL = "http://127.0.0.1:136" // 替换为你的服务器 IP
const debugMode = true                   // 调试开关，开启会输出详细流式拉取过程

var (
	currentHash, currentEventIDs, hostname string
	// 从 5 分钟前开始抓取，避免重启拉取太久的历史数据
	lastLogTime            = time.Now().UTC().Add(-5 * time.Minute)
	mu                     sync.RWMutex
	isInstalled            int32 = 0
	lastEventIDs           string
	lastCommand            string
	wasUninstalledManually bool

	modadvapi32              = syscall.NewLazyDLL("advapi32.dll")
	procCheckTokenMembership = modadvapi32.NewProc("CheckTokenMembership")
)

type ConfigResp struct {
	EventIDs string `json:"event_ids"`
	Command  string `json:"command"`
}

// 2. 增加封装好的 HTTP 请求函数（自动带上 Token）
func sendPost(url string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+AgentToken) // 注入 Token
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}
func sendGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+AgentToken)
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// 3. 增加书签的读取与保存逻辑
func loadBookmark() time.Time {
	data, err := os.ReadFile(bookmarkFile)
	if err == nil {
		if t, err := time.Parse(time.RFC3339Nano, string(data)); err == nil {
			logInfo("加载本地书签成功，从 %s 继续读取", t.Local().Format("2006-01-02 15:04:05"))
			return t
		}
	}
	// 如果没有书签，默认从 5 分钟前开始
	return time.Now().UTC().Add(-5 * time.Minute)
}

func saveBookmark(t time.Time) {
	os.WriteFile(bookmarkFile, []byte(t.Format(time.RFC3339Nano)), 0644)
}

// --- 日志系统封装 ---
func logDebug(format string, v ...interface{}) {
	if debugMode {
		fmt.Printf("[DEBUG] %s: "+format+"\n", append([]interface{}{time.Now().Format("15:04:05")}, v...)...)
	}
}

func logInfo(format string, v ...interface{}) {
	fmt.Printf("[INFO] %s: "+format+"\n", append([]interface{}{time.Now().Format("15:04:05")}, v...)...)
}

func logError(format string, v ...interface{}) {
	fmt.Printf("[ERROR] %s: "+format+"\n", append([]interface{}{time.Now().Format("15:04:05")}, v...)...)
}

// 释放内嵌 Sysmon
func extractSysmon() string {
	sysmonPath := filepath.Join(getAgentDir(), "Sysmon64.exe")
	data, err := sysmonAssets.ReadFile("bin/Sysmon64.exe")
	if err != nil {
		logError("读取内嵌资源失败: %v", err)
		return sysmonPath
	}
	_ = os.WriteFile(sysmonPath, data, 0755)
	return sysmonPath
}

// 权限检查
func isAdmin() bool {
	sid, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return false
	}
	var isMember int32
	ret, _, _ := procCheckTokenMembership.Call(0, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&isMember)))
	return ret != 0 && isMember != 0
}

func getAgentDir() string {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	if strings.Contains(dir, "Temp") {
		dir, _ = os.Getwd()
	}
	return dir
}

func isSysmonInstalled() bool {
	for _, svc := range []string{"Sysmon64", "Sysmon"} {
		cmd := exec.Command("sc", "query", svc)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), "SERVICE_NAME") {
			return true
		}
	}
	return false
}

func uninstallSysmon() {
	logInfo("开始卸载 Sysmon...")
	if isSysmonInstalled() {
		sysmonPath := extractSysmon()
		cmd := exec.Command(sysmonPath, "-u", "force")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()
		logInfo("Sysmon 已成功注销")
		atomic.StoreInt32(&isInstalled, 0)
	}

	agentDir := getAgentDir()
	filesToClean := []string{
		filepath.Join(agentDir, "config.xml"),
		filepath.Join(agentDir, "Sysmon64.exe"),
	}
	for _, f := range filesToClean {
		os.Remove(f)
	}
}

func ackCommand() {
	payload, _ := json.Marshal(map[string]string{"hostname": hostname, "command": ""})
	sendPost(ServerURL+"/api/web/command", payload) // ✅ 改用你封装的 sendPost
}

func applyConfig(cfg ConfigResp) {
	if cfg.EventIDs == "" {
		uninstallSysmon()
		return
	}

	confPath := filepath.Join(getAgentDir(), "config.xml")
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Sysmon schemaversion=\"4.91\">\n  <EventFiltering>\n")

	tags := []struct{ id, name string }{
		{"1", "ProcessCreate"}, {"2", "FileCreateTime"}, {"3", "NetworkConnect"}, {"5", "ProcessTerminate"},
		{"7", "ImageLoad"}, {"11", "FileCreate"}, {"12", "RegistryEvent"}, {"15", "FileCreateStreamHash"},
		{"22", "DnsQuery"}, {"23", "FileDelete"}, {"25", "ProcessTampering"},
	}

	selected := "," + cfg.EventIDs + ","
	for _, t := range tags {
		active := strings.Contains(selected, ","+t.id+",")
		if t.name == "RegistryEvent" && (strings.Contains(selected, ",12,") || strings.Contains(selected, ",13,") || strings.Contains(selected, ",14,")) {
			active = true
		}

		// 【重点优化】: 开启网络监控时，利用 Sysmon 驱动直接过滤域控等高频噪音 IP
		if t.name == "NetworkConnect" && active {
			sb.WriteString(`    <NetworkConnect onmatch="exclude">
      <!-- 在此过滤掉目标域控 IP 或安全设备的 IP，直接消除噪音 -->
      <DestinationIp condition="is">10.2.16.10</DestinationIp>
      <DestinationIp condition="is">10.2.16.11</DestinationIp>
    </NetworkConnect>` + "\n")
		} else if active {
			sb.WriteString(fmt.Sprintf("    <%s onmatch=\"exclude\" />\n", t.name))
		} else {
			sb.WriteString(fmt.Sprintf("    <%s onmatch=\"include\" />\n", t.name))
		}
	}
	sb.WriteString("  </EventFiltering>\n</Sysmon>")
	newConfigContent := []byte(sb.String())

	oldConfigContent, err := os.ReadFile(confPath)
	if err == nil && string(oldConfigContent) == string(newConfigContent) && isSysmonInstalled() {
		logDebug("配置无变化且服务正常运行，跳过应用。")
		atomic.StoreInt32(&isInstalled, 1)
		return
	}

	_ = os.WriteFile(confPath, newConfigContent, 0644)
	sysmonPath := extractSysmon()

	var cmd *exec.Cmd
	if !isSysmonInstalled() {
		logInfo("正在全新安装 Sysmon 服务...")
		cmd = exec.Command(sysmonPath, "-i", confPath, "-accepteula")
	} else {
		logInfo("正在更新 Sysmon 内核规则...")
		cmd = exec.Command(sysmonPath, "-c", confPath)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "already installed") {
			atomic.StoreInt32(&isInstalled, 1)
		} else {
			logError("Sysmon 指令执行失败: %v, 输出: %s", err, string(output))
		}
		return
	}

	logInfo("Sysmon 规则下发并生效成功! IDs: %s", cfg.EventIDs)
	atomic.StoreInt32(&isInstalled, 1)
	os.Remove(confPath)
}

// 【核心大重构】完全弃用 PowerShell，使用 Windows 原生 wevtutil 分页拉取
func pushLogs() {

	for {
		time.Sleep(10 * time.Second) // 每 10 秒唤醒一次

		if atomic.LoadInt32(&isInstalled) == 0 {
			continue
		}

		mu.RLock()
		ids := currentEventIDs
		mu.RUnlock()

		if ids == "" {
			continue
		}

		// 组装 XPath 语法进行精确过滤
		idSlice := strings.Split(ids, ",")
		var idConds []string
		for _, id := range idSlice {
			idConds = append(idConds, fmt.Sprintf("EventID=%s", id))
		}
		idQuery := strings.Join(idConds, " or ")

		// --- 进入高频分页拉取循环 ---
		for {
			// Windows Event Log 必须严格使用 UTC 时间对比
			ts := lastLogTime.UTC().Format("2006-01-02T15:04:05.000Z")
			query := fmt.Sprintf(`*[System[(%s) and TimeCreated[@SystemTime>'%s']]]`, idQuery, ts)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			// /c:200 表示每次最多拉 200 条，杜绝 OOM；/rd:false 表示正序(最老的在前)
			cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
				"/q:"+query, "/c:200", "/rd:false", "/e:root")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

			out, err := cmd.CombinedOutput()
			cancel()

			if err != nil {
				logDebug("查询日志为空或超时: %v", err)
				break // 跳出内层循环，等10秒再试
			}

			// 使用正则光速提取原生 XML，不再用 Go 慢慢解析结构体
			eventRe := regexp.MustCompile(`(?s)<Event\b.*?</Event>`)
			events := eventRe.FindAllString(string(out), -1)

			if len(events) == 0 {
				break // 最新数据已追平，跳出内层分页，进入10秒休眠
			}

			logDebug("拉取到 %d 条原生日志分块，正在打包...", len(events))

			timeRe := regexp.MustCompile(`SystemTime=["']([^"']+)["']`)
			var payload []map[string]string
			var maxTime time.Time

			for _, evtStr := range events {
				payload = append(payload, map[string]string{"xml": evtStr})
				// 提取最后一条记录的时间戳
				tmMatch := timeRe.FindStringSubmatch(evtStr)
				if len(tmMatch) > 1 {
					if pt, err := time.Parse(time.RFC3339Nano, tmMatch[1]); err == nil {
						if pt.After(maxTime) {
							maxTime = pt
						}
					}
				}
			}

			jsonBody, _ := json.Marshal(payload)
			resp, err := sendPost(ServerURL+"/api/agent/logs", jsonBody) 
			if err == nil {
				// ✅ 核心修复：只要没报错，不管状态码是多少，必须关闭 Body 释放连接！
				resp.Body.Close() 

				if resp.StatusCode == 200 {
					if !maxTime.IsZero() {
						lastLogTime = maxTime
						saveBookmark(maxTime) // 发送成功后，将进度落盘
					}
					logInfo("成功向服务器推送 %d 条, 当前指针进度: %s", len(events), maxTime.Local().Format("15:04:05"))
				} else {
					logError("服务器拒绝接收, 状态码: %d", resp.StatusCode)
					break
				}
			} else {
				logError("日志发送失败: %v", err)
				break
			}
						// 如果抓到的数量不足 200，说明“积压”的数据已抽干
			if len(events) < 200 {
				break
			}
			
			// 如果刚好是 200 条，说明系统里大概率还有积压的日志！
			// 不要休眠！瞬间开启下一次内层循环拉取！
			logDebug("数据量已满 200，无缝拉取下一页...")
		}
	}
}

func main() {
	if !isAdmin() {
		exePath, _ := os.Executable()
		fmt.Println("-------------------------------------------------------")
		fmt.Println("【系统提示】程序需要管理员权限。正在尝试提权...")
		fmt.Println("-------------------------------------------------------")
		cmd := exec.Command("runas", "/user:Administrator", exePath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Run()
		return
	}

	hostname, _ = os.Hostname()
	logInfo("Agent 核心启动成功 (主机:%s) [管理员权限]", hostname)
	lastLogTime = loadBookmark() // 初始化时读取书签
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		uninstallSysmon()
		os.Exit(0)
	}()

	go pushLogs()

	for {
		payload, _ := json.Marshal(map[string]string{"hostname": hostname})
		resp, err := sendPost(ServerURL+"/api/agent/heartbeat", payload)
		if err != nil {
			logError("无法连接服务器主控节点: 20秒后重试...")
			time.Sleep(20 * time.Second)
			continue
		}
		if resp != nil {
			resp.Body.Close()
		}

		resp, err = sendGet(ServerURL + "/api/agent/domains?hostname=" + hostname)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			h := sha256.Sum256(body)
			newHash := hex.EncodeToString(h[:])

			if newHash != currentHash {
				var cfg ConfigResp
				if err := json.Unmarshal(body, &cfg); err == nil {
					if cfg.Command == "uninstall" {
						logInfo("收到服务器 [自我卸载] 指令...")
						uninstallSysmon()
						ackCommand()
						logInfo("环境清理完毕，Agent 退出进程.")
						os.Exit(0)
					} else {
						if cfg.EventIDs != lastEventIDs || (!wasUninstalledManually && !isSysmonInstalled()) {
							logInfo("探测到新策略或组件缺失，正在应用...")
							applyConfig(cfg)
							
							lastEventIDs = cfg.EventIDs
							wasUninstalledManually = false
							mu.Lock()
							currentEventIDs = cfg.EventIDs
							mu.Unlock()
						}
					}
					currentHash = newHash
				}
			}
		} else {
			logError("获取配置失败: %v", err)
		}
		time.Sleep(20 * time.Second)
	}
}