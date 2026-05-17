package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

var appLog *log.Logger

//go:embed frontend/*
var frontendFS embed.FS

func initLogger() {
	f, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open app.log: %v", err)
		return
	}
	appLog = log.New(f, "", log.LstdFlags)
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
}

func logf(format string, args ...any) {
	if appLog != nil {
		appLog.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

type Connection struct {
	Proto  string `json:"proto"`
	Proc   string `json:"proc"`
	PID    uint32 `json:"pid"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
}

type ProxyConfig struct {
	ProxyURL     string        `json:"proxyUrl,omitempty"` // legacy single-proxy config
	Device       string        `json:"device"`
	Processes    []string      `json:"processes,omitempty"` // legacy process-name routing
	Proxies      []ProxyEntry  `json:"proxies"`
	Applications []Application `json:"applications"`
}

type ProxyEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Application struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	ProcessName string `json:"processName"`
	ProxyID     string `json:"proxyId,omitempty"` // legacy
	Proxy       string `json:"proxy"`
}

const (
	proxyConfigPath = "proxy_config.json"
	defaultDevice   = "tun://mytun"
)

var (
	proxyEngineMu      sync.Mutex
	proxyEngineRunning bool
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logf("websocket upgrade error from %s: %v", r.RemoteAddr, err)
		return
	}
	logf("websocket connected: %s", r.RemoteAddr)
	defer conn.Close()

	for {
		var list []Connection

		// TCP v4
		tcpRows, err := getTCPTable()
		if err == nil {
			for _, row := range tcpRows {
				list = append(list, Connection{
					Proto:  "TCP",
					Proc:   getProcessName(row.OwningPid),
					PID:    row.OwningPid,
					Local:  fmt.Sprintf("%s:%d", formatIP(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort))),
					Remote: fmt.Sprintf("%s:%d", formatIP(row.RemoteAddr), windows.Ntohs(uint16(row.RemotePort))),
					State:  tcpState(row.State),
				})
			}
		}

		// TCP v6
		tcp6Rows, err := getTCP6Table()
		if err == nil {
			for _, row := range tcp6Rows {
				list = append(list, Connection{
					Proto:  "TCP6",
					Proc:   getProcessName(row.OwningPid),
					PID:    row.OwningPid,
					Local:  fmt.Sprintf("%s:%d", formatIP6(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort))),
					Remote: fmt.Sprintf("%s:%d", formatIP6(row.RemoteAddr), windows.Ntohs(uint16(row.RemotePort))),
					State:  tcpState(row.State),
				})
			}
		}

		// UDP v4
		udpRows, err := getUDPTable()
		if err == nil {
			for _, row := range udpRows {
				list = append(list, Connection{
					Proto:  "UDP",
					Proc:   getProcessName(row.OwningPid),
					PID:    row.OwningPid,
					Local:  fmt.Sprintf("%s:%d", formatIP(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort))),
					Remote: "*",
					State:  "-",
				})
			}
		}

		// UDP v6
		udp6Rows, err := getUDP6Table()
		if err == nil {
			for _, row := range udp6Rows {
				list = append(list, Connection{
					Proto:  "UDP6",
					Proc:   getProcessName(row.OwningPid),
					PID:    row.OwningPid,
					Local:  fmt.Sprintf("%s:%d", formatIP6(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort))),
					Remote: "*",
					State:  "-",
				})
			}
		}

		if err := conn.WriteJSON(list); err != nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
}

func handleRecognize(w http.ResponseWriter, r *http.Request) {
	logf("recognize request from %s", r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(10 << 20) // 10MB
	if err != nil {
		logf("recognize parse multipart error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		logf("recognize form file error: %v", err)
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	logf("recognize processing file=%s size=%d", handler.Filename, handler.Size)

	ext := strings.ToLower(filepath.Ext(handler.Filename))
	var procName string

	if ext == ".exe" {
		procName = handler.Filename
	} else if ext == ".lnk" {
		// Use shortcut name without extension as a high-quality fallback
		shortcutName := strings.TrimSuffix(handler.Filename, filepath.Ext(handler.Filename))

		// Save to temp file to resolve
		tempFile, err := os.CreateTemp("", "*.lnk")
		if err != nil {
			logf("recognize create temp file error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(tempFile.Name())

		if _, err = io.Copy(tempFile, file); err != nil {
			tempFile.Close()
			logf("recognize save temp file error: %v", err)
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
		tempFile.Close()

		logf("recognize resolving shortcut temp=%s original=%s", tempFile.Name(), shortcutName)
		target, err := resolveLNK(tempFile.Name())

		if err != nil {
			logf("recognize shortcut resolution failed: %v; fallback=%s", err, shortcutName)
			procName = shortcutName
		} else {
			targetBase := filepath.Base(target)
			logf("recognize shortcut resolved file=%s target=%s", handler.Filename, target)

			// Smart logic: if target is something generic like 'javaw.exe' or 'cmd.exe',
			// the shortcut name might be more useful. Otherwise, the exe name is best for network monitoring.
			lowTarget := strings.ToLower(targetBase)
			if lowTarget == "" || lowTarget == "javaw.exe" || lowTarget == "java.exe" || lowTarget == "cmd.exe" || lowTarget == "python.exe" {
				procName = shortcutName
			} else {
				procName = targetBase
			}
		}
	} else {
		logf("recognize unsupported extension: %s", ext)
		http.Error(w, "Unsupported file type", http.StatusBadRequest)
		return
	}

	logf("recognize success process=%s", procName)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"proc": "%s"}`, procName)
}

func loadProxyConfig() ProxyConfig {
	data, err := os.ReadFile(proxyConfigPath)
	if err != nil {
		return normalizeProxyConfig(ProxyConfig{})
	}
	var config ProxyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		logf("proxy config load error: %v", err)
		return ProxyConfig{}
	}
	return normalizeProxyConfig(config)
}

func saveProxyConfig(config ProxyConfig) error {
	config = normalizeProxyConfig(config)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(proxyConfigPath, data, 0644)
}

func normalizeProxyConfig(config ProxyConfig) ProxyConfig {
	config.ProxyURL = strings.TrimSpace(config.ProxyURL)
	config.Device = strings.TrimSpace(config.Device)
	if config.Device == "" || config.Device == "wintun://mytun" {
		config.Device = defaultDevice
	}

	proxies := make([]ProxyEntry, 0, len(config.Proxies)+1)
	proxyIDs := make(map[string]struct{}, len(config.Proxies)+1)
	for _, item := range config.Proxies {
		item.ID = strings.TrimSpace(item.ID)
		item.Name = strings.TrimSpace(item.Name)
		item.URL = strings.TrimSpace(item.URL)
		if item.URL == "" {
			continue
		}
		if item.ID == "" {
			item.ID = fmt.Sprintf("proxy-%d", len(proxies)+1)
		}
		if item.Name == "" {
			item.Name = proxyDisplayName(item.URL)
		}
		if _, exists := proxyIDs[item.ID]; exists {
			continue
		}
		proxyIDs[item.ID] = struct{}{}
		proxies = append(proxies, item)
	}
	if len(proxies) == 0 && config.ProxyURL != "" {
		proxies = append(proxies, ProxyEntry{ID: "proxy-1", Name: "Основной", URL: config.ProxyURL})
		proxyIDs["proxy-1"] = struct{}{}
	}
	config.Proxies = proxies

	apps := make([]Application, 0, len(config.Applications))
	appSeen := make(map[string]struct{}, len(config.Applications))
	for _, app := range config.Applications {
		app.Name = strings.TrimSpace(app.Name)
		app.Path = strings.TrimSpace(app.Path)
		app.ProcessName = strings.TrimSpace(app.ProcessName)
		if app.ProcessName == "" && app.Path != "" {
			app.ProcessName = filepath.Base(app.Path)
		}
		if app.Name == "" && app.Path != "" {
			app.Name = strings.TrimSuffix(filepath.Base(app.Path), filepath.Ext(app.Path))
		}
		if app.ProcessName == "" {
			continue
		}
		app.ProxyID = strings.TrimSpace(app.ProxyID)
		app.Proxy = strings.TrimSpace(app.Proxy)
		if app.Proxy == "" && app.ProxyID != "" {
			for _, item := range proxies {
				if item.ID == app.ProxyID {
					app.Proxy = item.URL
					break
				}
			}
		}
		if app.ProxyID == "" && len(proxies) > 0 {
			app.ProxyID = proxies[0].ID
		}
		if app.ProxyID != "" {
			if _, ok := proxyIDs[app.ProxyID]; !ok && len(proxies) > 0 {
				app.ProxyID = proxies[0].ID
			}
		}
		key := strings.ToLower(app.ProcessName + "|" + app.Path)
		if _, ok := appSeen[key]; ok {
			continue
		}
		appSeen[key] = struct{}{}
		apps = append(apps, app)
	}
	config.Processes = nil
	config.Applications = apps
	return config
}

func handleProxyConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadProxyConfig())
	case http.MethodPost:
		var config ProxyConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config = normalizeProxyConfig(config)
		if err := saveProxyConfig(config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logf("proxy config updated proxies=%d device=%s applications=%d", len(config.Proxies), config.Device, len(config.Applications))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleProxyEngineStatus(w http.ResponseWriter, r *http.Request) {
	proxyEngineMu.Lock()
	running := proxyEngineRunning
	proxyEngineMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"running": running})
}

func handleProxyEngineStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := loadProxyConfig()
	if len(config.Proxies) == 0 || config.Device == "" {
		logf("proxy engine start rejected: missing proxies or device")
		http.Error(w, "at least one proxy and device are required", http.StatusBadRequest)
		return
	}
	proxyEngineMu.Lock()
	defer proxyEngineMu.Unlock()
	if proxyEngineRunning {
		logf("proxy engine start rejected: already running")
		http.Error(w, "proxy engine already running", http.StatusConflict)
		return
	}

	engine.Insert(&engine.Key{
		Device:   config.Device,
		Proxy:    normalizedProxyOrRaw(config.Proxies[0].URL),
		LogLevel: "info",
	})
	if err := engine.StartWithError(); err != nil {
		logf("proxy engine start failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := engine.EnablePIDRouting(); err != nil {
		logf("pid router enable failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyEngineRunning = true
	logf("proxy engine started device=%s proxies=%d mode=pid", config.Device, len(config.Proxies))
	w.WriteHeader(http.StatusNoContent)
}

func handleProxyEngineStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	proxyEngineMu.Lock()
	defer proxyEngineMu.Unlock()
	if !proxyEngineRunning {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := engine.StopWithError(); err != nil {
		logf("proxy engine stop failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logf("proxy engine stopped by user")
	proxyEngineRunning = false
	w.WriteHeader(http.StatusNoContent)
}

func handleProxyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProxyID string `json:"proxyId"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	config := loadProxyConfig()
	proxyURL := ""
	for _, item := range config.Proxies {
		if req.ProxyID == "" || item.ID == req.ProxyID {
			proxyURL = item.URL
			break
		}
	}
	normalizedProxyURL, err := normalizeProxyAddress(proxyURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := url.Parse(normalizedProxyURL)
	if err != nil || u.Host == "" {
		http.Error(w, "invalid proxy url", http.StatusBadRequest)
		return
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		logf("proxy test failed proxy=%s error=%v", proxyURL, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	conn.Close()
	logf("proxy test succeeded proxy=%s", proxyURL)
	w.WriteHeader(http.StatusNoContent)
}

func chooseExecutable() (string, error) {
	script := `
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.ShowInTaskbar = $false
$owner.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
$owner.Show()
$owner.Hide()
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Filter = 'Applications (*.exe)|*.exe'
$d.Title = 'Выберите приложение'
$d.Multiselect = $false
if ($d.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { $d.FileName }
$owner.Dispose()
`
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", fmt.Errorf("selection cancelled")
	}
	return path, nil
}

func normalizeProxyAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("proxy is required")
	}
	if strings.Contains(raw, "://") {
		return raw, nil
	}
	parts := strings.Split(raw, ":")
	if len(parts) == 4 {
		host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
		if host == "" || port == "" || user == "" || pass == "" {
			return "", fmt.Errorf("proxy must be in host:port:login:password format")
		}
		return fmt.Sprintf("http://%s:%s@%s:%s", url.QueryEscape(user), url.QueryEscape(pass), host, port), nil
	}
	return "socks5://" + raw, nil
}

func normalizedProxyOrRaw(raw string) string {
	normalized, err := normalizeProxyAddress(raw)
	if err != nil {
		return raw
	}
	return normalized
}

func proxyDisplayName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "Новый прокси"
	}
	if !strings.Contains(raw, "://") {
		parts := strings.Split(raw, ":")
		if len(parts) >= 2 {
			return parts[0] + ":" + parts[1]
		}
	}
	normalized, err := normalizeProxyAddress(raw)
	if err != nil {
		return raw
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return raw
	}
	return u.Host
}

func handleChooseExecutable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path, err := chooseExecutable()
	if err != nil {
		logf("choose executable failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	app := Application{
		Name:        strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		Path:        path,
		ProcessName: filepath.Base(path),
	}
	config := loadProxyConfig()
	config.Applications = append(config.Applications, app)
	if err := saveProxyConfig(config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logf("application added path=%s", path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(normalizeProxyConfig(config))
}

func handleApplications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadProxyConfig().Applications)
	case http.MethodPost:
		var app Application
		if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config := loadProxyConfig()
		config.Applications = append(config.Applications, app)
		if err := saveProxyConfig(config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logf("application added from catalog path=%s", app.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(normalizeProxyConfig(config))
	case http.MethodDelete:
		var app Application
		if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config := loadProxyConfig()
		filtered := config.Applications[:0]
		for _, current := range config.Applications {
			if !strings.EqualFold(current.Path, app.Path) && !strings.EqualFold(current.ProcessName, app.ProcessName) {
				filtered = append(filtered, current)
			}
		}
		config.Applications = filtered
		if err := saveProxyConfig(config); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logf("application removed path=%s process=%s", app.Path, app.ProcessName)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(normalizeProxyConfig(config))
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleApplicationCatalog(w http.ResponseWriter, r *http.Request) {
	script := `$roots=@("$env:APPDATA\Microsoft\Windows\Start Menu\Programs","$env:ProgramData\Microsoft\Windows\Start Menu\Programs"); $sh=New-Object -ComObject WScript.Shell; Get-ChildItem $roots -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object { $t=$sh.CreateShortcut($_.FullName).TargetPath; if($t -like '*.exe'){ [PSCustomObject]@{name=$_.BaseName;path=$t;processName=[IO.Path]::GetFileName($t)} } } | Sort-Object name -Unique | Select-Object -First 200 | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		raw = "[]"
	}
	if !strings.HasPrefix(raw, "[") {
		raw = "[" + raw + "]"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(raw))
}

func handleLaunchApplication(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var app Application
	if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if app.Path == "" {
		http.Error(w, "application path is required", http.StatusBadRequest)
		return
	}
	config := loadProxyConfig()
	if strings.TrimSpace(app.Proxy) == "" {
		http.Error(w, "application proxy is not configured", http.StatusBadRequest)
		return
	}
	if !proxyEngineRunning {
		engine.Insert(&engine.Key{
			Device:   config.Device,
			Proxy:    normalizedProxyOrRaw(app.Proxy),
			LogLevel: "info",
		})
		if err := engine.StartWithError(); err != nil {
			logf("proxy engine autostart failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := engine.EnablePIDRouting(); err != nil {
			logf("pid router enable failed during launch: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		proxyEngineRunning = true
		logf("proxy engine autostarted for application launch device=%s", config.Device)
	}
	cmd := exec.Command(app.Path)
	if err := cmd.Start(); err != nil {
		logf("application launch failed path=%s error=%v", app.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := engine.SetPIDProxy(uint32(cmd.Process.Pid), normalizedProxyOrRaw(app.Proxy), app.Name); err != nil {
		logf("application pid route failed path=%s pid=%d error=%v", app.Path, cmd.Process.Pid, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logf("application launched path=%s pid=%d proxy=%s", app.Path, cmd.Process.Pid, proxyDisplayName(app.Proxy))
	w.WriteHeader(http.StatusNoContent)
}

func handleLogTail(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("app.log")
	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 80 {
		lines = lines[len(lines)-80:]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(strings.Join(lines, "\n")))
}

func resolveLNK(path string) (string, error) {
	// Escape single quotes for PowerShell
	escapedPath := strings.ReplaceAll(path, "'", "''")
	script := fmt.Sprintf(`$sh = New-Object -ComObject WScript.Shell; $s = $sh.CreateShortcut('%s'); $s.TargetPath`, escapedPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("powershell resolution timed out")
		}
		return "", err
	}
	res := strings.TrimSpace(string(out))
	if res == "" {
		return "", fmt.Errorf("shortcut has no target")
	}
	return res, nil
}

func appURL() string {
	return "http://localhost:8006"
}

func openAppWindow() {
	if err := exec.Command("cmd", "/c", "start", "msedge", "--app="+appURL()).Start(); err != nil {
		logf("open app window failed: %v", err)
		return
	}
	logf("open app window requested")
}

func existingInstanceRunning() bool {
	client := http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(appURL() + "/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return err == nil && resp.StatusCode == http.StatusOK && string(body) == "pong"
}

func main() {
	if existingInstanceRunning() {
		initLogger()
		logf("existing instance detected; reopening UI")
		openAppWindow()
		return
	}

	initLogger()
	logf("application startup version=single-exe os=%s arch=%s", runtime.GOOS, runtime.GOARCH)
	hideConsole()
	noBrowser := flag.Bool("no-browser", false, "Do not open browser on startup")
	flag.Parse()

	frontendRoot, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", noCache(http.FileServer(http.FS(frontendRoot))))
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})
	mux.HandleFunc("/ws", handleConnections)
	mux.HandleFunc("/recognize", handleRecognize)
	mux.HandleFunc("/proxy-config", handleProxyConfig)
	mux.HandleFunc("/proxy-engine/status", handleProxyEngineStatus)
	mux.HandleFunc("/proxy-engine/start", handleProxyEngineStart)
	mux.HandleFunc("/proxy-engine/stop", handleProxyEngineStop)
	mux.HandleFunc("/proxy-test", handleProxyTest)
	mux.HandleFunc("/applications", handleApplications)
	mux.HandleFunc("/applications/catalog", handleApplicationCatalog)
	mux.HandleFunc("/applications/choose-exe", handleChooseExecutable)
	mux.HandleFunc("/applications/launch", handleLaunchApplication)
	mux.HandleFunc("/log-tail", handleLogTail)
	mux.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		logf("restart requested")
		executable, err := os.Executable()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Create new process arguments, ensuring -no-browser is present
		args := []string{"-no-browser"}
		for _, arg := range os.Args[1:] {
			if arg != "-no-browser" {
				args = append(args, arg)
			}
		}

		cmd := exec.Command(executable, args...)
		err = cmd.Start()
		if err != nil {
			logf("restart failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logf("restart child started pid=%d", cmd.Process.Pid)
		os.Exit(0)
	})
	mux.HandleFunc("/exit", func(w http.ResponseWriter, r *http.Request) {
		logf("exit requested")
		os.Exit(0)
	})

	if !*noBrowser {
		go func() {
			time.Sleep(1 * time.Second)
			openAppWindow()
		}()
	}

	logf("server starting addr=:8006 noBrowser=%v", *noBrowser)
	log.Fatal(http.ListenAndServe(":8006", logRequests(mux)))
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logf("http method=%s path=%s remote=%s duration=%s", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func tcpState(s uint32) string {
	states := map[uint32]string{
		1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTAB",
		6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
		11: "TIME_WAIT", 12: "DELETE_TCB",
	}
	if v, ok := states[s]; ok {
		return v
	}
	return fmt.Sprintf("%d", s)
}
