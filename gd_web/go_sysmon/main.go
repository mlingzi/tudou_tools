package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
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

// 1. 全局 Token 和 书签文件路径
const AgentToken = "Sysmon-EDR-Super-Secret-Token-2026"
var bookmarkFile = filepath.Join(getAgentDir(), "bookmark.dat")

//go:embed bin/Sysmon64.exe
var sysmonAssets embed.FS

// --- 全局配置区域 ---

// 【需求修改】: 支持纯 IP:Port，程序会自动先尝试 HTTPS，再尝试 HTTP
var ServerNodes = []string{
	"127.0.0.1:136",             // 不带前缀，会自动探测 HTTPS -> HTTP
	"10.2.16.121:136",           // 不带前缀，会自动探测 HTTPS -> HTTP
	"https://43.128.130.45:50888", // 你也可以强制指定带前缀的地址
}

const debugMode = true 

var (
	currentHash, currentEventIDs, hostname string
	lastLogTime            = time.Now().UTC().Add(-5 * time.Minute)
	mu                     sync.RWMutex
	isInstalled            int32 = 0
	lastEventIDs           string
	lastCommand            string
	wasUninstalledManually bool

	activeURL string
	urlMu     sync.RWMutex

	modadvapi32              = syscall.NewLazyDLL("advapi32.dll")
	procCheckTokenMembership = modadvapi32.NewProc("CheckTokenMembership")
)

type ConfigResp struct {
	EventIDs string `json:"event_ids"`
	Command  string `json:"command"`
}

var secureClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

func getActiveURL() string {
	urlMu.RLock()
	defer urlMu.RUnlock()
	return activeURL
}

func setActiveURL(url string) {
	urlMu.Lock()
	defer urlMu.Unlock()
	activeURL = url
}

func sendPost(url string, payload []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+AgentToken)
	return secureClient.Do(req)
}

func sendGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+AgentToken)
	return secureClient.Do(req)
}

func loadBookmark() time.Time {
	data, err := os.ReadFile(bookmarkFile)
	if err == nil {
		if t, err := time.Parse(time.RFC3339Nano, string(data)); err == nil {
			logInfo("加载本地书签成功，从 %s 继续读取", t.Local().Format("2006-01-02 15:04:05"))
			return t
		}
	}
	return time.Now().UTC().Add(-5 * time.Minute)
}

func saveBookmark(t time.Time) {
	os.WriteFile(bookmarkFile, []byte(t.Format(time.RFC3339Nano)), 0644)
}

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

// ✅ 卸载后的状态回传被正确封装在这里，不在 main 函数乱放了
func ackCommand() {
	currentURL := getActiveURL()
	if currentURL == "" {
		return
	}
	payload, _ := json.Marshal(map[string]string{"hostname": hostname})
	
	// 这里拼接了寻址时探测到的正确前缀 (http:// 或 https://)
	resp, err := sendPost(currentURL+"/api/agent/command/clear", payload)
	if err != nil {
		logError("回传卸载确认失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		logInfo("已成功向主控节点确认执行完毕，服务器卸载状态已重置")
	} else {
		logError("主控节点未能处理状态重置，HTTP 状态码: %d", resp.StatusCode)
	}
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

		if t.name == "NetworkConnect" && active {
			sb.WriteString(`    <NetworkConnect onmatch="exclude">
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
		// 防御性处理：底层驱动假卸载导致的安装报错，自动转为更新模式覆盖
		if strings.Contains(string(output), "already installed") {
			logInfo("检测到系统底层存在残留的 Sysmon 驱动，自动切换为规则覆盖模式...")
			cmd = exec.Command(sysmonPath, "-c", confPath)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if err2 := cmd.Run(); err2 == nil {
				atomic.StoreInt32(&isInstalled, 1)
				logInfo("Sysmon 残留驱动规则覆盖成功!")
				os.Remove(confPath)
				return
			}
		}
		logError("Sysmon 指令执行失败: %v, 输出: %s", err, string(output))
		return
	}

	logInfo("Sysmon 规则下发并生效成功! IDs: %s", cfg.EventIDs)
	atomic.StoreInt32(&isInstalled, 1)
	os.Remove(confPath)
}

func pushLogs() {
	for {
		time.Sleep(10 * time.Second)

		currentURL := getActiveURL()
		if currentURL == "" {
			continue
		}

		if atomic.LoadInt32(&isInstalled) == 0 {
			continue
		}

		mu.RLock()
		ids := currentEventIDs
		mu.RUnlock()

		if ids == "" {
			continue
		}

		idSlice := strings.Split(ids, ",")
		var idConds []string
		for _, id := range idSlice {
			idConds = append(idConds, fmt.Sprintf("EventID=%s", id))
		}
		idQuery := strings.Join(idConds, " or ")

		for {
			ts := lastLogTime.UTC().Format("2006-01-02T15:04:05.000Z")
			query := fmt.Sprintf(`*[System[(%s) and TimeCreated[@SystemTime>'%s']]]`, idQuery, ts)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := exec.CommandContext(ctx, "wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
				"/q:"+query, "/c:200", "/rd:false", "/e:root")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

			out, err := cmd.CombinedOutput()
			cancel()

			if err != nil {
				logDebug("查询日志为空或超时: %v", err)
				break
			}

			eventRe := regexp.MustCompile(`(?s)<Event\b.*?</Event>`)
			events := eventRe.FindAllString(string(out), -1)

			if len(events) == 0 {
				break
			}

			logDebug("拉取到 %d 条原生日志分块，正在打包...", len(events))

			timeRe := regexp.MustCompile(`SystemTime=["']([^"']+)["']`)
			var payload []map[string]string
			var maxTime time.Time

			for _, evtStr := range events {
				payload = append(payload, map[string]string{"xml": evtStr})
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
			
			currentURL = getActiveURL()
			if currentURL == "" {
				break
			}

			resp, err := sendPost(currentURL+"/api/agent/logs", jsonBody)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					if !maxTime.IsZero() {
						lastLogTime = maxTime
						saveBookmark(maxTime)
					}
					logInfo("成功向服务器推送 %d 条, 当前指针进度: %s", len(events), maxTime.Local().Format("15:04:05"))
				} else {
					logError("服务器拒绝接收, 状态码: %d", resp.StatusCode)
					break
				}
			} else {
				logError("日志发送失败: %v", err)
				setActiveURL("")
				break
			}
			
			if len(events) < 200 {
				break
			}
			
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
	lastLogTime = loadBookmark()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		uninstallSysmon()
		os.Exit(0)
	}()

	go pushLogs()

	// 主控心跳与配置同步循环
	for {
		currentURL := getActiveURL()
		payload, _ := json.Marshal(map[string]string{"hostname": hostname})

		// 如果当前没有活跃的 URL，开启【带协议智能探测】的轮询寻址模式
		if currentURL == "" {
			found := false
			for _, node := range ServerNodes {
				var urlsToTry []string
				
				// 如果自带了 http/https 前缀，就按指定的来
				if strings.HasPrefix(node, "http://") || strings.HasPrefix(node, "https://") {
					urlsToTry = append(urlsToTry, node)
				} else {
					// 核心升级：如果没有前缀，先探 https，失败了瞬间回退探 http
					urlsToTry = append(urlsToTry, "https://"+node, "http://"+node)
				}

				for _, u := range urlsToTry {
					resp, err := sendPost(u+"/api/agent/heartbeat", payload)
					if err == nil {
						if resp != nil {
							resp.Body.Close()
						}
						// 寻址成功，将其设为活跃地址 (此时的 u 已经带有正确的 http/https 前缀)
						setActiveURL(u)
						currentURL = u
						logInfo("寻址成功，探测通信协议成功，当前使用节点: %s", u)
						found = true
						break
					}
				}
				if found {
					break
				}
			}

			if !found {
				logError("所有备用服务器(含 HTTP/HTTPS 协议)均无法连接，20秒后重试...")
				time.Sleep(20 * time.Second)
				continue
			}
		} else {
			resp, err := sendPost(currentURL+"/api/agent/heartbeat", payload)
			if err != nil {
				logError("当前服务器(%s)连接断开，准备重新寻址...", currentURL)
				setActiveURL("") 
				continue
			}
			if resp != nil {
				resp.Body.Close()
			}
		}

		// 心跳成功后，拉取策略并校验 Hash
		resp, err := sendGet(currentURL + "/api/agent/domains?hostname=" + hostname)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			h := sha256.Sum256(body)
			newHash := hex.EncodeToString(h[:])

			if newHash != currentHash {
				var cfg ConfigResp
				if err := json.Unmarshal(body, &cfg); err == nil {
					
					// ==== 这里的卸载逻辑才是完美无 BUG 的 ====
					if cfg.Command == "uninstall" {
						logInfo("收到服务器 [自我卸载] 指令...")
						uninstallSysmon()
						
						// 【重点】这里才是唯一调用回传确认的地方！
						ackCommand() 
						
						time.Sleep(1 * time.Second) // 留时间给网络请求发出去
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
			setActiveURL("") 
		}
		
		time.Sleep(20 * time.Second)
	}
}