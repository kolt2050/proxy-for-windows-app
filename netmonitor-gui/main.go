package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/base64"
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
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	tunlog "github.com/xjasonlyu/tun2socks/v2/log"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

var appLog *log.Logger
var startupLog *log.Logger

var appVersion = "dev"

//go:embed frontend/*
var frontendFS embed.FS

//go:embed assets/wintun.dll
var embeddedWintunDLL []byte

func initLogger() {
	path, err := appDataPath("app.log")
	if err != nil {
		log.Printf("failed to resolve app.log path: %v", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open app.log: %v", err)
		return
	}
	appLog = log.New(f, "", log.LstdFlags)
	appLog.Println("------------------------------------------")
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags)
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{path}
	cfg.ErrorOutputPaths = []string{path}
	if logger, err := cfg.Build(); err == nil {
		tunlog.SetLogger(logger)
	}
}

func initStartupLogger() {
	path, err := appDataPath("startup.log")
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	startupLog = log.New(f, "", log.LstdFlags)
}

func appDataPath(name string) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(executable), name), nil
}

func shortcutLogPath(id string) (string, error) {
	base, err := appDataPath("shortcut-logs")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(base, 0755); err != nil {
		return "", err
	}
	return filepath.Join(base, id+".log"), nil
}

func profilesRoot() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ProxyForApp", "profiles"), nil
}

func startupLogf(format string, args ...any) {
	if startupLog != nil {
		startupLog.Printf(format, args...)
	}
}

func logf(format string, args ...any) {
	if appLog != nil {
		appLog.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func shortcutLogf(app Application, format string, args ...any) {
	if strings.TrimSpace(app.ID) == "" {
		return
	}
	path, err := shortcutLogPath(app.ID)
	if err != nil {
		logf("shortcut log path failed id=%s error=%v", app.ID, err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logf("shortcut log open failed id=%s error=%v", app.ID, err)
		return
	}
	defer f.Close()
	log.New(f, "", log.LstdFlags).Printf(format, args...)
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
	ID          string `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	ProcessName string `json:"processName"`
	ProxyID     string `json:"proxyId,omitempty"` // legacy
	Proxy       string `json:"proxy"`
}

type ProxyMetadata struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
}

const (
	proxyConfigPath = "proxy_config.json"
	defaultDevice   = "tun://mytun"
)

var (
	proxyEngineMu      sync.Mutex
	proxyEngineRunning bool
	uiHeartbeatMu      sync.Mutex
	lastUIHeartbeat    time.Time
	uiSeen             bool
	busyOperations     int
	networkState       *tunNetworkState
	proxyMetadataCache sync.Map
	launchedAppsMu     sync.Mutex
	launchedApps       = make(map[string]launchedApplication)
)

type tunNetworkState struct {
	Gateway    string
	ProxyHosts map[string]struct{}
}

type launchedApplication struct {
	InstanceID      string
	App             Application
	Cmd             *exec.Cmd
	ProfileDir      string
	Chromium        bool
	KeepBridgeAlive bool
	Bridge          *browserProxyBridge
}

type browserProxySettings struct {
	Scheme   string
	Host     string
	Port     int
	Username string
	Password string
}

type browserProxyBridge struct {
	listener net.Listener
	server   *http.Server
	upstream *url.URL
	app      Application
}

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
	for _, app := range config.Applications {
		app.ID = strings.TrimSpace(app.ID)
		if app.ID == "" {
			app.ID = uuid.NewString()
		}
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
	shutdownLaunchedApplications("proxy-engine-stop")
	cleanupTunNetwork()
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
		Proxy   string `json:"proxy"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	config := loadProxyConfig()
	proxyURL := strings.TrimSpace(req.Proxy)
	if proxyURL == "" {
		for _, item := range config.Proxies {
			if req.ProxyID == "" || item.ID == req.ProxyID {
				proxyURL = item.URL
				break
			}
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

func handleProxyMetadata(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.URL.Query().Get("proxy"))
	if raw == "" {
		http.Error(w, "proxy is required", http.StatusBadRequest)
		return
	}
	host, err := proxyHost(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	meta := ProxyMetadata{IP: host}
	if cached, ok := proxyMetadataCache.Load(host); ok {
		cachedMeta := cached.(ProxyMetadata)
		meta.Country = cachedMeta.Country
		meta.CountryCode = cachedMeta.CountryCode
	} else if lookedUp, err := lookupCountry(host); err == nil {
		meta.Country = lookedUp.Country
		meta.CountryCode = lookedUp.CountryCode
		proxyMetadataCache.Store(host, lookedUp)
	} else {
		logf("proxy metadata lookup failed ip=%s error=%v", host, err)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func lookupCountry(ip string) (ProxyMetadata, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + url.PathEscape(ip) + "?fields=status,message,country,countryCode")
	if err != nil {
		return ProxyMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ProxyMetadata{}, fmt.Errorf("geo lookup status %s", resp.Status)
	}
	var payload struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Country string `json:"country"`
		Code    string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ProxyMetadata{}, err
	}
	if payload.Status != "success" {
		return ProxyMetadata{}, fmt.Errorf("geo lookup failed: %s", payload.Message)
	}
	return ProxyMetadata{IP: ip, Country: strings.TrimSpace(payload.Country), CountryCode: strings.TrimSpace(payload.Code)}, nil
}

func handleApplicationIcon(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Query().Get("path"))
	if path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Drawing
$icon=[System.Drawing.Icon]::ExtractAssociatedIcon('%s')
if($null -eq $icon){ exit 1 }
$bmp=$icon.ToBitmap()
$ms=New-Object System.IO.MemoryStream
$bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
[Convert]::ToBase64String($ms.ToArray())
`, strings.ReplaceAll(path, "'", "''"))
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		http.Error(w, strings.TrimSpace(string(out)), http.StatusNotFound)
		return
	}
	data, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(strings.TrimSpace(string(out)))))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data)
}

func chooseBackupPath(save bool) (string, error) {
	dialogType := "OpenFileDialog"
	if save {
		dialogType = "SaveFileDialog"
	}
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$d = New-Object System.Windows.Forms.%s
$d.Filter = 'ProxyForApp backup (*.pfabackup)|*.pfabackup'
$d.DefaultExt = 'pfabackup'
$d.AddExtension = $true
if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
  $path = $d.FileName
  $root = [System.IO.Path]::GetPathRoot($path)
  if($root -match '^([A-Za-z]):\\'){
    $drive = Get-PSDrive -Name $Matches[1] -ErrorAction SilentlyContinue
    if($drive -and $drive.DisplayRoot){
      $path = Join-Path $drive.DisplayRoot $path.Substring($root.Length)
    }
  }
  [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($path))
}
`, dialogType)
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-Command", script).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	path, err := decodePowerShellUTF16Base64(strings.TrimSpace(string(out)))
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("selection cancelled")
	}
	return path, nil
}

func decodePowerShellUTF16Base64(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	if len(data)%2 != 0 {
		return "", fmt.Errorf("invalid utf16 path data")
	}
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	return strings.TrimSpace(string(utf16.Decode(words))), nil
}

func handleExportBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	done := beginBusyOperation()
	defer done()
	path, err := chooseBackupPath(true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	shutdownLaunchedApplications("export-backup")
	if err := exportBackup(path); err != nil {
		logf("backup export failed path=%s error=%v", path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logf("backup exported path=%s", path)
	w.WriteHeader(http.StatusNoContent)
}

func exportBackup(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := writeBackupArchive(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpPath, path)
}

func writeBackupArchive(f *os.File) error {
	zw := zip.NewWriter(f)

	configData, err := json.MarshalIndent(loadProxyConfig(), "", "  ")
	if err != nil {
		return err
	}
	entry, err := zw.Create("proxy_config.json")
	if err != nil {
		return err
	}
	if _, err := entry.Write(configData); err != nil {
		return err
	}

	root, err := profilesRoot()
	if err != nil {
		return err
	}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return zw.Close()
	}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if shouldSkipBackupEntry(rel) {
			return nil
		}
		out, err := zw.Create(filepath.ToSlash(filepath.Join("profiles", rel)))
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}); err != nil {
		return err
	}
	return zw.Close()
}

func shouldSkipBackupEntry(rel string) bool {
	parts := strings.FieldsFunc(filepath.ToSlash(rel), func(r rune) bool { return r == '/' })
	if len(parts) < 2 {
		return false
	}
	profileRel := strings.Join(parts[1:], "/")
	for dir := range chromiumCacheDirs() {
		if profileRel == dir || strings.HasPrefix(profileRel, dir+"/") || strings.Contains(profileRel, "/"+dir+"/") {
			return true
		}
	}
	return false
}

func chromiumCacheDirs() map[string]struct{} {
	return map[string]struct{}{
		"ActorSafetyLists":                            {},
		"AutofillAiModelCache":                        {},
		"CertificateRevocation":                       {},
		"component_crx_cache":                         {},
		"Crashpad":                                    {},
		"Crowd Deny":                                  {},
		"Default/Cache":                               {},
		"Default/Code Cache":                          {},
		"Default/DawnGraphiteCache":                   {},
		"Default/DawnWebGPUCache":                     {},
		"Default/GPUCache":                            {},
		"Default/JumpListIconsMostVisited":            {},
		"Default/JumpListIconsRecentClosed":           {},
		"Default/optimization_guide_hint_cache_store": {},
		"Default/Safe Browsing Network":               {},
		"Default/Service Worker/CacheStorage":         {},
		"Default/Shared Dictionary":                   {},
		"Default/VideoDecodeStats":                    {},
		"GrShaderCache":                               {},
		"GraphiteDawnCache":                           {},
		"hyphen-data":                                 {},
		"OnDeviceHeadSuggestModel":                    {},
		"OptGuideOnDeviceClassifierModel":             {},
		"OptGuideOnDeviceModel":                       {},
		"OptimizationHints":                           {},
		"optimization_guide_model_store":              {},
		"PKIMetadata":                                 {},
		"Safe Browsing":                               {},
		"ShaderCache":                                 {},
		"Subresource Filter":                          {},
		"WasmTtsEngine":                               {},
		"Webstore Downloads":                          {},
		"ZxcvbnData":                                  {},
	}
}

func handleImportBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	done := beginBusyOperation()
	defer done()
	path, err := chooseBackupPath(false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	shutdownLaunchedApplications("import-backup")
	if err := importBackup(path); err != nil {
		logf("backup import failed path=%s error=%v", path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	config := loadProxyConfig()
	logf("backup imported path=%s applications=%d", path, len(config.Applications))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func importBackup(path string) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return describeBackupOpenError(path, err)
	}
	defer zr.Close()
	profiles, err := profilesRoot()
	if err != nil {
		return err
	}
	configFound := false
	for _, file := range zr.File {
		switch {
		case file.Name == "proxy_config.json":
			configFound = true
			rc, err := file.Open()
			if err != nil {
				return err
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return err
			}
			var config ProxyConfig
			if err := json.Unmarshal(data, &config); err != nil {
				return err
			}
			if err := saveProxyConfig(config); err != nil {
				return err
			}
		case strings.HasPrefix(file.Name, "profiles/") && !file.FileInfo().IsDir():
			rel := strings.TrimPrefix(file.Name, "profiles/")
			target := filepath.Join(profiles, filepath.FromSlash(rel))
			cleanProfiles, err := filepath.Abs(profiles)
			if err != nil {
				return err
			}
			cleanTarget, err := filepath.Abs(target)
			if err != nil {
				return err
			}
			if cleanTarget != cleanProfiles && !strings.HasPrefix(cleanTarget, cleanProfiles+string(os.PathSeparator)) {
				return fmt.Errorf("backup contains invalid profile path: %s", file.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			rc, err := file.Open()
			if err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				rc.Close()
				return err
			}
			_, copyErr := io.Copy(out, rc)
			rc.Close()
			out.Close()
			if copyErr != nil {
				return copyErr
			}
		}
	}
	if !configFound {
		return fmt.Errorf("backup does not contain proxy_config.json")
	}
	return nil
}

func describeBackupOpenError(path string, openErr error) error {
	f, err := os.Open(path)
	if err != nil {
		return openErr
	}
	defer f.Close()

	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	if n >= 2 && bytes.Equal(head[:2], []byte("PK")) {
		if hasZipEndOfCentralDirectory(f) {
			return fmt.Errorf("backup zip cannot be opened: %w", openErr)
		}
		return fmt.Errorf("backup archive is incomplete; create a new export with version %s or newer", appVersion)
	}
	return fmt.Errorf("selected file is not a ProxyForApp backup zip: %w", openErr)
}

func hasZipEndOfCentralDirectory(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	size := info.Size()
	if size <= 0 {
		return false
	}
	const maxEOCDSearch = int64(65557)
	start := int64(0)
	if size > maxEOCDSearch {
		start = size - maxEOCDSearch
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil {
		return false
	}
	return bytes.Contains(buf, []byte{0x50, 0x4b, 0x05, 0x06})
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
		ID:          uuid.NewString(),
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
		if strings.TrimSpace(app.ID) == "" {
			app.ID = uuid.NewString()
		}
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
			if current.ID != app.ID {
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

func handleClearApplicationCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var app Application
	if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(app.ID) == "" {
		http.Error(w, "application id is required", http.StatusBadRequest)
		return
	}
	name := strings.ToLower(filepath.Base(app.Path))
	if !isChromiumBrowser(name) || isVSCode(name) {
		http.Error(w, "cache cleanup is available only for managed Chromium browsers", http.StatusBadRequest)
		return
	}
	profileDir, err := managedChromiumProfileDir(app)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	probe := launchedApplication{App: app, ProfileDir: profileDir, Chromium: true}
	pids, err := chromiumPIDs(probe)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(pids) > 0 {
		logf("closing managed Chromium before cache cleanup id=%s profile=%s pids=%v", app.ID, profileDir, pids)
		shortcutLogf(app, "CLOSING managed Chromium before cache cleanup pids=%v", pids)
		if err := closeChromiumProfileProcesses(app, probe, pids); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	removed, err := clearManagedChromiumCache(profileDir)
	if err != nil {
		logf("managed Chromium cache cleanup failed id=%s profile=%s error=%v", app.ID, profileDir, err)
		shortcutLogf(app, "ERROR cache cleanup failed error=%v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	logf("managed Chromium cache cleaned id=%s profile=%s removed=%d", app.ID, profileDir, removed)
	shortcutLogf(app, "CACHE cleaned removed=%d", removed)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"removed": removed})
}

func clearManagedChromiumCache(profileDir string) (int, error) {
	cleanProfile, err := filepath.Abs(profileDir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for dir := range chromiumCacheDirs() {
		target := filepath.Join(cleanProfile, filepath.FromSlash(dir))
		if !pathInside(target, cleanProfile) {
			return removed, fmt.Errorf("refusing to remove path outside profile: %s", target)
		}
		if _, err := os.Stat(target); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, err
		}
		if err := os.RemoveAll(target); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func pathInside(path, root string) bool {
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
	proxyBridgeApp := usesProxyBridgeMode(strings.ToLower(filepath.Base(app.Path)))
	if !proxyBridgeApp && !proxyEngineRunning {
		engine.Insert(&engine.Key{
			Device:   config.Device,
			Proxy:    normalizedProxyOrRaw(app.Proxy),
			LogLevel: "info",
		})
		if err := engine.StartWithError(); err != nil {
			logf("proxy engine autostart failed: %v", err)
			shortcutLogf(app, "ERROR proxy engine autostart failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := engine.EnablePIDRouting(); err != nil {
			logf("pid router enable failed during launch: %v", err)
			shortcutLogf(app, "ERROR pid router enable failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := configureTunNetwork(app.Proxy); err != nil {
			_ = engine.StopWithError()
			logf("tun network setup failed: %v", err)
			shortcutLogf(app, "ERROR tun network setup failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		proxyEngineRunning = true
		logf("proxy engine autostarted for application launch device=%s", config.Device)
	} else if !proxyBridgeApp {
		if err := ensureProxyBypassRoute(app.Proxy); err != nil {
			logf("proxy bypass route setup failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			shortcutLogf(app, "ERROR proxy bypass route setup failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if proxyEngineRunning {
		if err := ensureProxyBypassRoute(app.Proxy); err != nil {
			logf("browser proxy bypass route setup failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			shortcutLogf(app, "ERROR browser proxy bypass route setup failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	name := strings.ToLower(filepath.Base(app.Path))
	if isChromiumBrowser(name) && !isVSCode(name) {
		if err := ensureChromiumProfileReadyForLaunch(app); err != nil {
			logf("chromium profile preparation failed id=%s path=%s error=%v", app.ID, app.Path, err)
			shortcutLogf(app, "ERROR chromium profile preparation failed proxy=%s error=%v", proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	cmd, profileDir, proxyBridgeMode, bridge, err := buildLaunchCommand(app)
	if err != nil {
		logf("application launch setup failed path=%s error=%v", app.Path, err)
		shortcutLogf(app, "ERROR launch setup failed path=%s error=%v", app.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := cmd.Start(); err != nil {
		logf("application launch failed path=%s error=%v", app.Path, err)
		shortcutLogf(app, "ERROR launch failed path=%s error=%v", app.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	instance := launchedApplication{
		InstanceID:      uuid.NewString(),
		App:             app,
		Cmd:             cmd,
		ProfileDir:      profileDir,
		Chromium:        proxyBridgeMode,
		KeepBridgeAlive: isVSCode(strings.ToLower(filepath.Base(app.Path))),
		Bridge:          bridge,
	}
	if proxyBridgeMode {
		if err := waitForProfileProcesses(instance, 4*time.Second); err != nil {
			if bridge != nil {
				_ = bridge.Close()
			}
			logf("application launch did not create managed profile process path=%s pid=%d profile=%s error=%v", app.Path, cmd.Process.Pid, profileDir, err)
			shortcutLogf(app, "ERROR launch did not create managed profile process pid=%d profile=%s error=%v", cmd.Process.Pid, profileDir, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if !proxyBridgeMode {
		if err := engine.SetPIDProxy(uint32(cmd.Process.Pid), normalizedProxyOrRaw(app.Proxy), app.Name); err != nil {
			logf("application pid route failed path=%s pid=%d error=%v", app.Path, cmd.Process.Pid, err)
			shortcutLogf(app, "ERROR pid route failed path=%s pid=%d proxy=%s error=%v", app.Path, cmd.Process.Pid, proxyDisplayName(app.Proxy), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	launchedAppsMu.Lock()
	if previous, ok := launchedApps[app.ID]; ok && previous.InstanceID != instance.InstanceID && previous.Bridge != nil {
		_ = previous.Bridge.Close()
	}
	launchedApps[app.ID] = instance
	launchedAppsMu.Unlock()
	logf("APP OPENED name=%q id=%s launchPid=%d proxy=%s", app.Name, app.ID, cmd.Process.Pid, proxyDisplayName(app.Proxy))
	shortcutLogf(app, "------------------------------------------")
	shortcutLogf(app, "OPENED name=%q launchPid=%d proxy=%s", app.Name, cmd.Process.Pid, proxyDisplayName(app.Proxy))
	go monitorLaunchedApplication(instance)
	w.WriteHeader(http.StatusNoContent)
}

func monitorLaunchedApplication(item launchedApplication) {
	if item.Chromium {
		monitorChromiumApplication(item)
		return
	}
	err := item.Cmd.Wait()
	removeLaunchedApplication(item)
	if err != nil {
		logf("APP CLOSED name=%q id=%s pid=%d proxy=%s error=%v", item.App.Name, item.App.ID, item.Cmd.Process.Pid, proxyDisplayName(item.App.Proxy), err)
		shortcutLogf(item.App, "CLOSED name=%q pid=%d proxy=%s error=%v", item.App.Name, item.Cmd.Process.Pid, proxyDisplayName(item.App.Proxy), err)
		return
	}
	logf("APP CLOSED name=%q id=%s pid=%d proxy=%s", item.App.Name, item.App.ID, item.Cmd.Process.Pid, proxyDisplayName(item.App.Proxy))
	shortcutLogf(item.App, "CLOSED name=%q pid=%d proxy=%s", item.App.Name, item.Cmd.Process.Pid, proxyDisplayName(item.App.Proxy))
}

func waitForProfileProcesses(item launchedApplication, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		pids, err := chromiumPIDs(item)
		if err != nil {
			lastErr = err
		} else if len(pids) > 0 {
			return nil
		}
		if item.Cmd.ProcessState != nil && item.Cmd.ProcessState.Exited() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("managed profile process was not found")
}

func monitorChromiumApplication(item launchedApplication) {
	_ = item.Cmd.Wait()
	seen := false
	deadline := time.Now().Add(5 * time.Second)
	for {
		pids, err := chromiumPIDs(item)
		if err != nil {
			logf("chromium monitor failed id=%s proxy=%s error=%v", item.App.ID, proxyDisplayName(item.App.Proxy), err)
			shortcutLogf(item.App, "ERROR chromium monitor failed proxy=%s error=%v", proxyDisplayName(item.App.Proxy), err)
			time.Sleep(time.Second)
			continue
		}
		if len(pids) > 0 {
			seen = true
		} else if seen {
			removeLaunchedApplication(item)
			logf("APP CLOSED name=%q id=%s proxy=%s", item.App.Name, item.App.ID, proxyDisplayName(item.App.Proxy))
			shortcutLogf(item.App, "CLOSED name=%q proxy=%s", item.App.Name, proxyDisplayName(item.App.Proxy))
			return
		} else if time.Now().After(deadline) {
			removeLaunchedApplication(item)
			logf("APP CLOSED name=%q id=%s proxy=%s reason=no-managed-profile-process", item.App.Name, item.App.ID, proxyDisplayName(item.App.Proxy))
			shortcutLogf(item.App, "CLOSED name=%q proxy=%s reason=no-managed-profile-process", item.App.Name, proxyDisplayName(item.App.Proxy))
			return
		}
		time.Sleep(time.Second)
	}
}

func ensureChromiumProfileReadyForLaunch(app Application) error {
	profileDir, err := managedChromiumProfileDir(app)
	if err != nil {
		return err
	}
	probe := launchedApplication{App: app, ProfileDir: profileDir}
	pids, err := chromiumPIDs(probe)
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return nil
	}

	launchedAppsMu.Lock()
	item, tracked := launchedApps[app.ID]
	launchedAppsMu.Unlock()
	if tracked && item.Bridge != nil && item.Chromium && normalizedProxyOrRaw(item.App.Proxy) == normalizedProxyOrRaw(app.Proxy) {
		return nil
	}

	reason := "stale unmanaged profile"
	if tracked {
		reason = fmt.Sprintf("proxy changed old=%s new=%s", proxyDisplayName(item.App.Proxy), proxyDisplayName(app.Proxy))
	}
	logf("closing managed Chromium profile before relaunch id=%s profile=%s reason=%s pids=%v", app.ID, profileDir, reason, pids)
	shortcutLogf(app, "CLOSING managed Chromium before relaunch reason=%s pids=%v", reason, pids)
	if err := closeChromiumProfileProcesses(app, probe, pids); err != nil {
		return err
	}
	if tracked {
		removeLaunchedApplication(item)
	}
	return nil
}

func closeChromiumProfileProcesses(app Application, item launchedApplication, pids []int) error {
	for _, pid := range pids {
		if out, err := runWindowsCommandUTF8("taskkill", "/PID", fmt.Sprint(pid), "/T"); err != nil {
			logf("managed Chromium graceful close failed id=%s pid=%d proxy=%s error=%v output=%s", app.ID, pid, proxyDisplayName(app.Proxy), err, strings.TrimSpace(string(out)))
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		remaining, err := chromiumPIDs(item)
		if err != nil {
			return err
		}
		if len(remaining) == 0 {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	remaining, err := chromiumPIDs(item)
	if err != nil {
		return err
	}
	for _, pid := range remaining {
		if out, err := runWindowsCommandUTF8("taskkill", "/F", "/PID", fmt.Sprint(pid), "/T"); err != nil {
			return fmt.Errorf("force close managed Chromium pid=%d: %w: %s", pid, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func managedChromiumProfileDir(app Application) (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ProxyForApp", "profiles", app.ID), nil
}

func managedVSCodeProfileDir(app Application) (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ProxyForApp", "profiles", app.ID, "vscode-user-data", "Code"), nil
}

func removeLaunchedApplication(item launchedApplication) {
	launchedAppsMu.Lock()
	current, ok := launchedApps[item.App.ID]
	if ok && current.InstanceID == item.InstanceID {
		delete(launchedApps, item.App.ID)
	} else {
		ok = false
	}
	launchedAppsMu.Unlock()
	if ok && item.Bridge != nil {
		_ = item.Bridge.Close()
	}
}

func processPIDs(name string) ([]int, error) {
	safeName := strings.ReplaceAll(name, "'", "''")
	script := fmt.Sprintf("Get-CimInstance Win32_Process -Filter \"Name='%s'\" | Select-Object -ExpandProperty ProcessId", safeName)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("query process pids: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		var pid int
		if _, err := fmt.Sscan(line, &pid); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func rootApplicationPIDs(item launchedApplication) []int {
	if item.Chromium {
		pids, err := chromiumPIDs(item)
		if err == nil && len(pids) > 0 {
			return pids[:1]
		}
	}
	return []int{item.Cmd.Process.Pid}
}

func chromiumPIDs(item launchedApplication) ([]int, error) {
	name := strings.ToLower(filepath.Base(item.App.Path))
	profile := strings.ReplaceAll(item.ProfileDir, "'", "''")
	script := fmt.Sprintf("Get-CimInstance Win32_Process -Filter \"Name='%s'\" | Where-Object { $_.CommandLine -like '*%s*' } | Select-Object -ExpandProperty ProcessId", name, profile)
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("query chromium pids: %w: %s", err, strings.TrimSpace(string(out)))
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		var pid int
		if _, err := fmt.Sscan(line, &pid); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func shutdownLaunchedApplications(reason string) {
	launchedAppsMu.Lock()
	items := make([]launchedApplication, 0, len(launchedApps))
	for _, item := range launchedApps {
		if isVSCode(strings.ToLower(filepath.Base(item.App.Path))) {
			logf("leaving VS Code running during shutdown id=%s proxy=%s reason=%s", item.App.ID, proxyDisplayName(item.App.Proxy), reason)
			shortcutLogf(item.App, "LEAVING VS Code running reason=%s", reason)
			continue
		}
		items = append(items, item)
	}
	launchedAppsMu.Unlock()
	if len(items) == 0 {
		return
	}

	logf("closing launched applications reason=%s count=%d", reason, len(items))
	for _, item := range items {
		for _, pid := range rootApplicationPIDs(item) {
			logf("APP CLOSING name=%q id=%s pid=%d proxy=%s reason=%s", item.App.Name, item.App.ID, pid, proxyDisplayName(item.App.Proxy), reason)
			shortcutLogf(item.App, "CLOSING name=%q pid=%d proxy=%s reason=%s", item.App.Name, pid, proxyDisplayName(item.App.Proxy), reason)
			if out, err := runWindowsCommandUTF8("taskkill", "/PID", fmt.Sprint(pid), "/T"); err != nil {
				logf("application graceful close request failed id=%s pid=%d proxy=%s error=%v output=%s", item.App.ID, pid, proxyDisplayName(item.App.Proxy), err, strings.TrimSpace(string(out)))
				shortcutLogf(item.App, "ERROR graceful close failed pid=%d proxy=%s error=%v output=%s", pid, proxyDisplayName(item.App.Proxy), err, strings.TrimSpace(string(out)))
			}
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		launchedAppsMu.Lock()
		remaining := len(launchedApps)
		launchedAppsMu.Unlock()
		if remaining == 0 {
			logf("all launched applications closed gracefully reason=%s", reason)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	launchedAppsMu.Lock()
	items = items[:0]
	for _, item := range launchedApps {
		items = append(items, item)
	}
	launchedAppsMu.Unlock()
	for _, item := range items {
		for _, pid := range rootApplicationPIDs(item) {
			logf("APP FORCE CLOSING name=%q id=%s pid=%d proxy=%s reason=%s", item.App.Name, item.App.ID, pid, proxyDisplayName(item.App.Proxy), reason)
			shortcutLogf(item.App, "FORCE CLOSING name=%q pid=%d proxy=%s reason=%s", item.App.Name, pid, proxyDisplayName(item.App.Proxy), reason)
			if out, err := runWindowsCommandUTF8("taskkill", "/F", "/PID", fmt.Sprint(pid), "/T"); err != nil {
				logf("application force close failed id=%s pid=%d proxy=%s error=%v output=%s", item.App.ID, pid, proxyDisplayName(item.App.Proxy), err, strings.TrimSpace(string(out)))
				shortcutLogf(item.App, "ERROR force close failed pid=%d proxy=%s error=%v output=%s", pid, proxyDisplayName(item.App.Proxy), err, strings.TrimSpace(string(out)))
			}
		}
	}
}

func buildLaunchCommand(app Application) (*exec.Cmd, string, bool, *browserProxyBridge, error) {
	name := strings.ToLower(filepath.Base(app.Path))
	if usesProxyBridgeMode(name) {
		root, err := os.UserConfigDir()
		if err != nil {
			return nil, "", false, nil, err
		}
		profileRoot := filepath.Join(root, "ProxyForApp", "profiles", app.ID)
		profileDir := profileRoot
		if isVSCode(name) {
			profileDir, err = managedVSCodeProfileDir(app)
			if err != nil {
				return nil, "", false, nil, err
			}
			profileRoot = filepath.Dir(profileDir)
		}
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			return nil, "", false, nil, err
		}
		settings, err := parseBrowserProxy(app.Proxy)
		if err != nil {
			return nil, "", false, nil, err
		}
		bridge, err := startBrowserProxyBridge(app, settings)
		if err != nil {
			return nil, "", false, nil, err
		}
		logf("browser proxy mode configured id=%s browser=%s proxy=%s", app.ID, name, proxyDisplayName(app.Proxy))
		shortcutLogf(app, "BROWSER PROXY MODE proxy=%s localBridge=%s", proxyDisplayName(app.Proxy), bridge.Addr())
		localProxy := "http://" + bridge.Addr()
		if isVSCode(name) {
			cmd, err := buildVSCodeCommand(app, profileRoot, profileDir, localProxy)
			if err != nil {
				_ = bridge.Close()
				return nil, "", false, nil, err
			}
			return cmd, profileDir, true, bridge, nil
		}
		return exec.Command(
			app.Path,
			"--user-data-dir="+profileDir,
			"--proxy-server="+localProxy,
			"--new-window",
			"--no-first-run",
		), profileDir, true, bridge, nil
	}
	return exec.Command(app.Path), "", false, nil, nil
}

func buildVSCodeCommand(app Application, profileRoot, userDataDir, localProxy string) (*exec.Cmd, error) {
	extensionsDir, err := vsCodeExtensionsDir(profileRoot)
	if err != nil {
		return nil, err
	}
	codexHome := filepath.Join(profileRoot, "codex-home")
	if err := os.MkdirAll(codexHome, 0755); err != nil {
		return nil, err
	}
	userSettingsDir := filepath.Join(userDataDir, "User")
	if err := os.MkdirAll(userSettingsDir, 0755); err != nil {
		return nil, err
	}
	settingsPath := filepath.Join(userSettingsDir, "settings.json")
	settings := map[string]any{}
	if existing, err := os.ReadFile(settingsPath); err == nil && len(strings.TrimSpace(string(existing))) > 0 {
		if err := json.Unmarshal(trimUTF8BOM(existing), &settings); err != nil {
			return nil, fmt.Errorf("read VS Code settings %s: %w", settingsPath, err)
		}
	}
	settings["http.proxy"] = localProxy
	settings["http.proxySupport"] = "override"
	settings["http.proxyStrictSSL"] = false
	removeLegacyVSCodeWindowOverrides(settings)
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return nil, err
	}
	cmd := exec.Command(
		app.Path,
		"--user-data-dir="+userDataDir,
		"--extensions-dir="+extensionsDir,
		"--proxy-server="+localProxy,
	)
	cmd.Env = vsCodeEnvironment(profileRoot, localProxy)
	return cmd, nil
}

func vsCodeExtensionsDir(profileRoot string) (string, error) {
	extensionsDir := filepath.Join(profileRoot, "extensions")
	if err := os.MkdirAll(extensionsDir, 0755); err != nil {
		return "", err
	}
	return extensionsDir, nil
}

func trimUTF8BOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
}

func removeLegacyVSCodeWindowOverrides(settings map[string]any) {
	if settings["window.restoreWindows"] == "none" {
		delete(settings, "window.restoreWindows")
	}
	if settings["window.openFoldersInNewWindow"] == "on" {
		delete(settings, "window.openFoldersInNewWindow")
	}
	if settings["window.openFilesInNewWindow"] == "on" {
		delete(settings, "window.openFilesInNewWindow")
	}
}

func vsCodeEnvironment(profileRoot, localProxy string) []string {
	codexHome := filepath.Join(profileRoot, "codex-home")
	return append(os.Environ(),
		"HTTP_PROXY="+localProxy,
		"HTTPS_PROXY="+localProxy,
		"ALL_PROXY="+localProxy,
		"http_proxy="+localProxy,
		"https_proxy="+localProxy,
		"all_proxy="+localProxy,
		"CODEX_HOME="+codexHome,
	)
}

func usesProxyBridgeMode(name string) bool {
	return isChromiumBrowser(name) || isVSCode(name)
}

func isChromiumBrowser(name string) bool {
	switch name {
	case "chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "opera.exe", "vivaldi.exe", "chromium.exe", "arc.exe":
		return true
	default:
		return false
	}
}

func isVSCode(name string) bool {
	return name == "code.exe"
}

func parseBrowserProxy(raw string) (browserProxySettings, error) {
	normalized, err := normalizeProxyAddress(raw)
	if err != nil {
		return browserProxySettings{}, err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return browserProxySettings{}, err
	}
	host := u.Hostname()
	portText := u.Port()
	if host == "" || portText == "" {
		return browserProxySettings{}, fmt.Errorf("browser proxy requires host and port")
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		return browserProxySettings{}, fmt.Errorf("invalid proxy port: %w", err)
	}
	password, _ := u.User.Password()
	return browserProxySettings{
		Scheme:   u.Scheme,
		Host:     host,
		Port:     port,
		Username: u.User.Username(),
		Password: password,
	}, nil
}

func startBrowserProxyBridge(app Application, settings browserProxySettings) (*browserProxyBridge, error) {
	upstream := &url.URL{
		Scheme: settings.Scheme,
		Host:   net.JoinHostPort(settings.Host, fmt.Sprint(settings.Port)),
		User:   url.UserPassword(settings.Username, settings.Password),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	bridge := &browserProxyBridge{listener: listener, upstream: upstream, app: app}
	bridge.server = &http.Server{Handler: bridge}
	go func() {
		_ = bridge.server.Serve(listener)
	}()
	return bridge, nil
}

func (b *browserProxyBridge) Addr() string {
	return b.listener.Addr().String()
}

func (b *browserProxyBridge) Close() error {
	return b.server.Close()
}

func (b *browserProxyBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		b.handleConnect(w, r)
		return
	}
	shortcutLogf(b.app, "BRIDGE HTTP method=%s url=%s", r.Method, r.URL.String())
	transport := &http.Transport{Proxy: http.ProxyURL(b.upstream)}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		shortcutLogf(b.app, "ERROR bridge HTTP request failed method=%s url=%s error=%v", r.Method, r.URL.String(), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		shortcutLogf(b.app, "BRIDGE HTTP RESPONSE method=%s url=%s status=%s", r.Method, r.URL.String(), resp.Status)
	}
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (b *browserProxyBridge) handleConnect(w http.ResponseWriter, r *http.Request) {
	logf("browser bridge CONNECT id=%s target=%s upstream=%s", b.app.ID, r.Host, b.upstream.Host)
	shortcutLogf(b.app, "BRIDGE CONNECT target=%s upstream=%s", r.Host, b.upstream.Host)
	upstreamConn, err := net.DialTimeout("tcp", b.upstream.Host, 10*time.Second)
	if err != nil {
		shortcutLogf(b.app, "NETWORK ERROR upstream proxy unavailable target=%s upstream=%s error=%v", r.Host, b.upstream.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: r.Host},
		Host:   r.Host,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}
	if b.upstream.User != nil {
		password, _ := b.upstream.User.Password()
		req.SetBasicAuth(b.upstream.User.Username(), password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err := req.Write(upstreamConn); err != nil {
		upstreamConn.Close()
		shortcutLogf(b.app, "NETWORK ERROR failed to send CONNECT target=%s error=%v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		upstreamConn.Close()
		shortcutLogf(b.app, "NETWORK ERROR invalid CONNECT response target=%s error=%v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		upstreamConn.Close()
		shortcutLogf(b.app, "NETWORK ERROR CONNECT rejected target=%s status=%s", r.Host, resp.Status)
		http.Error(w, resp.Status, resp.StatusCode)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		upstreamConn.Close()
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	started := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	go proxyCopy(&wg, b.app, r.Host, "client-to-upstream", upstreamConn, clientConn, started)
	go proxyCopy(&wg, b.app, r.Host, "upstream-to-client", clientConn, upstreamReader, started)
	go func() {
		wg.Wait()
		_ = upstreamConn.Close()
		_ = clientConn.Close()
	}()
}

func proxyCopy(wg *sync.WaitGroup, app Application, target, direction string, dst net.Conn, src io.Reader, started time.Time) {
	defer wg.Done()
	written, err := io.Copy(dst, src)
	closeWrite(dst)
	if err != nil && !isExpectedProxyCopyError(err) {
		logf("browser bridge tunnel copy failed id=%s target=%s direction=%s bytes=%d duration=%s error=%v", app.ID, target, direction, written, time.Since(started), err)
		shortcutLogf(app, "BRIDGE TUNNEL ERROR target=%s direction=%s bytes=%d duration=%s error=%v", target, direction, written, time.Since(started), err)
		return
	}
	if shouldLogProxyTunnel(target, written, time.Since(started)) {
		shortcutLogf(app, "BRIDGE TUNNEL CLOSED target=%s direction=%s bytes=%d duration=%s", target, direction, written, time.Since(started))
	}
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func isExpectedProxyCopyError(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "use of closed network connection") ||
		strings.Contains(text, "forcibly closed") ||
		strings.Contains(text, "wsacancelblockingcall")
}

func shouldLogProxyTunnel(target string, bytes int64, duration time.Duration) bool {
	if bytes > 1024*1024 || duration > 10*time.Second {
		return true
	}
	target = strings.ToLower(target)
	return strings.Contains(target, "gallery") ||
		strings.Contains(target, "vsassets") ||
		strings.Contains(target, "marketplace") ||
		strings.Contains(target, "openai")
}

func handleLogTail(w http.ResponseWriter, r *http.Request) {
	path, err := appDataPath("app.log")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := os.ReadFile(path)
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

func handleShortcutLog(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	path, err := shortcutLogPath(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	const max = 64 * 1024
	if len(data) > max {
		data = data[len(data)-max:]
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
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
	initStartupLogger()
	startupLogf("startup begin args=%q", os.Args[1:])
	elevated := isElevated()
	startupLogf("startup elevated=%v hasElevatedArg=%v", elevated, hasArg("--elevated"))
	if !elevated && !hasArg("--elevated") {
		startupLogf("startup requesting elevation")
		if err := relaunchElevated(); err != nil {
			startupLogf("startup elevation request failed: %v", err)
			initLogger()
			logf("elevation request failed: %v", err)
		} else {
			startupLogf("startup elevation request submitted")
		}
		return
	}

	if existingInstanceRunning() {
		initLogger()
		startupLogf("startup existing instance detected")
		logf("existing instance detected; reopening UI")
		openAppWindow()
		return
	}

	initLogger()
	startupLogf("startup entering main server")
	logf("application startup version=%s os=%s arch=%s", appVersion, runtime.GOOS, runtime.GOARCH)
	startupLogf("startup logger initialized")
	if err := ensureWintunDLL(); err != nil {
		logf("wintun setup failed: %v", err)
		startupLogf("startup wintun setup failed: %v", err)
	} else {
		startupLogf("startup wintun ready")
	}
	hideConsole()
	startupLogf("startup console hidden")
	noBrowser := flag.Bool("no-browser", false, "Do not open browser on startup")
	_ = flag.Bool("elevated", false, "Internal flag set after UAC relaunch")
	flag.Parse()
	startupLogf("startup flags parsed noBrowser=%v", *noBrowser)

	frontendRoot, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		startupLogf("startup frontend fs failed: %v", err)
		log.Fatal(err)
	}
	startupLogf("startup frontend fs ready")
	mux := http.NewServeMux()
	mux.Handle("/", noCache(http.FileServer(http.FS(frontendRoot))))
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"version": appVersion})
	})
	mux.HandleFunc("/ui-heartbeat", func(w http.ResponseWriter, r *http.Request) {
		uiHeartbeatMu.Lock()
		lastUIHeartbeat = time.Now()
		uiSeen = true
		uiHeartbeatMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/ws", handleConnections)
	mux.HandleFunc("/recognize", handleRecognize)
	mux.HandleFunc("/proxy-config", handleProxyConfig)
	mux.HandleFunc("/proxy-engine/status", handleProxyEngineStatus)
	mux.HandleFunc("/proxy-engine/start", handleProxyEngineStart)
	mux.HandleFunc("/proxy-engine/stop", handleProxyEngineStop)
	mux.HandleFunc("/proxy-test", handleProxyTest)
	mux.HandleFunc("/proxy-metadata", handleProxyMetadata)
	mux.HandleFunc("/application-icon", handleApplicationIcon)
	mux.HandleFunc("/backup/export", handleExportBackup)
	mux.HandleFunc("/backup/import", handleImportBackup)
	mux.HandleFunc("/applications", handleApplications)
	mux.HandleFunc("/applications/clear-cache", handleClearApplicationCache)
	mux.HandleFunc("/applications/catalog", handleApplicationCatalog)
	mux.HandleFunc("/applications/choose-exe", handleChooseExecutable)
	mux.HandleFunc("/applications/launch", handleLaunchApplication)
	mux.HandleFunc("/log-tail", handleLogTail)
	mux.HandleFunc("/shortcut-log", handleShortcutLog)
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
		shutdownLaunchedApplications("restart")
		cleanupTunNetwork()
		os.Exit(0)
	})
	mux.HandleFunc("/exit", func(w http.ResponseWriter, r *http.Request) {
		logf("exit requested")
		shutdownLaunchedApplications("exit")
		cleanupTunNetwork()
		os.Exit(0)
	})

	if !*noBrowser {
		go func() {
			time.Sleep(1 * time.Second)
			startupLogf("startup opening app window")
			openAppWindow()
		}()
	}

	go watchUIHeartbeat()

	logf("server starting addr=:8006 noBrowser=%v", *noBrowser)
	startupLogf("startup listen begin addr=:8006 noBrowser=%v", *noBrowser)
	log.Fatal(http.ListenAndServe(":8006", logRequests(mux)))
}

func hasArg(target string) bool {
	for _, arg := range os.Args[1:] {
		if arg == target {
			return true
		}
	}
	return false
}

func isElevated() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	); err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func relaunchElevated() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{}, os.Args[1:]...)
	args = append(args, "--elevated")
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(strings.Join(args, " "))
	if err != nil {
		return err
	}
	err = windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE)
	startupLogf("startup ShellExecute runas returned err=%v executable=%q params=%q", err, executable, strings.Join(args, " "))
	return err
}

func ensureWintunDLL() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(filepath.Dir(executable), "wintun.dll")
	current, err := os.ReadFile(target)
	if err == nil && bytes.Equal(current, embeddedWintunDLL) {
		return nil
	}
	if err := os.WriteFile(target, embeddedWintunDLL, 0644); err != nil {
		return err
	}
	logf("wintun.dll extracted path=%s", target)
	return nil
}

func watchUIHeartbeat() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		uiHeartbeatMu.Lock()
		seen := uiSeen
		lastSeen := lastUIHeartbeat
		busy := busyOperations > 0
		uiHeartbeatMu.Unlock()
		if busy {
			continue
		}
		if seen && time.Since(lastSeen) > 12*time.Second {
			if hasLaunchedApplications() {
				logf("ui heartbeat lost; keeping backend alive because launched applications are still tracked")
				uiHeartbeatMu.Lock()
				lastUIHeartbeat = time.Now()
				uiHeartbeatMu.Unlock()
				continue
			}
			logf("ui heartbeat lost; exiting application")
			shutdownLaunchedApplications("ui-heartbeat-lost")
			cleanupTunNetwork()
			os.Exit(0)
		}
	}
}

func hasLaunchedApplications() bool {
	launchedAppsMu.Lock()
	defer launchedAppsMu.Unlock()
	return len(launchedApps) > 0
}

func beginBusyOperation() func() {
	uiHeartbeatMu.Lock()
	busyOperations++
	uiHeartbeatMu.Unlock()
	return func() {
		uiHeartbeatMu.Lock()
		if busyOperations > 0 {
			busyOperations--
		}
		lastUIHeartbeat = time.Now()
		uiHeartbeatMu.Unlock()
	}
}

func configureTunNetwork(proxyRaw string) error {
	if networkState != nil {
		return ensureProxyBypassRoute(proxyRaw)
	}
	proxyHost, err := proxyHost(proxyRaw)
	if err != nil {
		return fmt.Errorf("resolve proxy host: %w", err)
	}
	gateway, err := defaultGateway()
	if err != nil {
		return fmt.Errorf("resolve default gateway: %w", err)
	}
	if err := runNetsh("interface", "ipv4", "set", "address", "name=mytun", "source=static", "addr=192.168.123.1", "mask=255.255.255.0"); err != nil {
		return err
	}
	if err := runNetsh("interface", "ipv4", "set", "dnsservers", "name=mytun", "static", "address=8.8.8.8", "register=none", "validate=no"); err != nil {
		return err
	}
	if err := runRoute("ADD", proxyHost, "MASK", "255.255.255.255", gateway, "METRIC", "1"); err != nil {
		return err
	}
	if err := runNetsh("interface", "ipv4", "add", "route", "0.0.0.0/0", "mytun", "192.168.123.1", "metric=1"); err != nil {
		_ = runRoute("DELETE", proxyHost)
		return err
	}
	networkState = &tunNetworkState{Gateway: gateway, ProxyHosts: map[string]struct{}{proxyHost: {}}}
	logf("tun network configured interface=mytun proxyHost=%s gateway=%s", proxyHost, gateway)
	logNetworkDiagnostics("after configure")
	return nil
}

func ensureProxyBypassRoute(proxyRaw string) error {
	if networkState == nil {
		return configureTunNetwork(proxyRaw)
	}
	host, err := proxyHost(proxyRaw)
	if err != nil {
		return fmt.Errorf("resolve proxy host: %w", err)
	}
	if _, exists := networkState.ProxyHosts[host]; exists {
		return nil
	}
	if err := runRoute("ADD", host, "MASK", "255.255.255.255", networkState.Gateway, "METRIC", "1"); err != nil {
		return err
	}
	networkState.ProxyHosts[host] = struct{}{}
	logf("tun proxy bypass route added proxyHost=%s gateway=%s", host, networkState.Gateway)
	return nil
}

func cleanupTunNetwork() {
	if networkState == nil {
		return
	}
	_ = runNetsh("interface", "ipv4", "delete", "route", "0.0.0.0/0", "mytun", "192.168.123.1")
	for host := range networkState.ProxyHosts {
		_ = runRoute("DELETE", host)
	}
	logf("tun network cleanup completed interface=mytun proxyHosts=%d", len(networkState.ProxyHosts))
	logNetworkDiagnostics("after cleanup")
	networkState = nil
}

func proxyHost(raw string) (string, error) {
	normalized, err := normalizeProxyAddress(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return "", fmt.Errorf("proxy host has no IPv4 address: %s", host)
}

func defaultGateway() (string, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop)`).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("query default gateway: %w: %s", err, strings.TrimSpace(string(out)))
	}
	gateway := strings.TrimSpace(string(out))
	if gateway == "" {
		return "", fmt.Errorf("default gateway not found")
	}
	return gateway, nil
}

func runNetsh(args ...string) error {
	out, err := runWindowsCommandUTF8("netsh", args...)
	if err != nil {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runRoute(args ...string) error {
	out, err := runWindowsCommandUTF8("route", args...)
	if err != nil {
		return fmt.Errorf("route %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func logNetworkDiagnostics(stage string) {
	logf("network diagnostic captured stage=%s", stage)
}

func runWindowsCommandUTF8(name string, args ...string) ([]byte, error) {
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, name)
	for _, arg := range args {
		quoted = append(quoted, `"`+strings.ReplaceAll(arg, `"`, `\"`)+`"`)
	}
	script := "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + strings.Join(quoted, " ")
	return exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path == "/ui-heartbeat" || r.URL.Path == "/log-tail" {
			return
		}
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
