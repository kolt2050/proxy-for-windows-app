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
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
)

var userLog *log.Logger

//go:embed frontend/*
var frontendFS embed.FS

func initLogger() {
	f, err := os.OpenFile("user_actions.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open user_actions.log: %v", err)
		return
	}
	userLog = log.New(f, "", log.LstdFlags)
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
	ProxyURL  string   `json:"proxyUrl"`
	Device    string   `json:"device"`
	Processes []string `json:"processes"`
}

const proxyConfigPath = "proxy_config.json"

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
		log.Println("Upgrade error:", err)
		return
	}
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
	if userLog != nil {
		userLog.Printf("Recognize: Handler hit from %s", r.RemoteAddr)
	}
	log.Printf("Recognize: incoming request from %s", r.RemoteAddr)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(10 << 20) // 10MB
	if err != nil {
		log.Printf("Recognize: ParseMultipartForm error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Printf("Recognize: error retrieving file from form: %v", err)
		if userLog != nil {
			userLog.Printf("Error: FormFile retrieval error: %v", err)
		}
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if userLog != nil {
		userLog.Printf("User action: Processing file %s (%d bytes)", handler.Filename, handler.Size)
	}
	log.Printf("Recognize: received file %s (%d bytes)", handler.Filename, handler.Size)

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
			log.Printf("Recognize: failed to create temp file: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(tempFile.Name())

		if _, err = io.Copy(tempFile, file); err != nil {
			tempFile.Close()
			log.Printf("Recognize: failed to save temp file: %v", err)
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
		tempFile.Close()

		log.Printf("Recognize: resolving shortcut %s (original name: %s)", tempFile.Name(), shortcutName)
		target, err := resolveLNK(tempFile.Name())

		if err != nil {
			log.Printf("Recognize: resolveLNK failed: %v. Falling back to shortcut name: %s", err, shortcutName)
			if userLog != nil {
				userLog.Printf("Info: Shortcut resolution failed (%v), using shortcut name: %s", err, shortcutName)
			}
			procName = shortcutName
		} else {
			targetBase := filepath.Base(target)
			log.Printf("Recognize: shortcut resolved to target: %s (base: %s)", target, targetBase)
			if userLog != nil {
				userLog.Printf("Recognition result: Shortcut %s resolved to %s", handler.Filename, target)
			}

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
		log.Printf("Recognize: unsupported file extension: %s", ext)
		http.Error(w, "Unsupported file type", http.StatusBadRequest)
		return
	}

	if ext == ".exe" && userLog != nil {
		userLog.Printf("Recognition result: Executable %s recognized", procName)
	}
	log.Printf("Recognize: success, identified process: %s", procName)
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
		log.Printf("Proxy config load error: %v", err)
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
	seen := make(map[string]struct{}, len(config.Processes))
	processes := make([]string, 0, len(config.Processes))
	for _, process := range config.Processes {
		process = strings.TrimSpace(process)
		if process == "" {
			continue
		}
		key := strings.ToLower(process)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		processes = append(processes, process)
	}
	config.ProxyURL = strings.TrimSpace(config.ProxyURL)
	config.Device = strings.TrimSpace(config.Device)
	config.Processes = processes
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
		if userLog != nil {
			userLog.Printf("Proxy config updated: proxy=%s processes=%v", config.ProxyURL, config.Processes)
		}
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
	if config.ProxyURL == "" || config.Device == "" {
		http.Error(w, "proxy and device are required", http.StatusBadRequest)
		return
	}
	if len(config.Processes) == 0 {
		http.Error(w, "at least one process is required", http.StatusBadRequest)
		return
	}
	proxyEngineMu.Lock()
	defer proxyEngineMu.Unlock()
	if proxyEngineRunning {
		http.Error(w, "proxy engine already running", http.StatusConflict)
		return
	}

	engine.Insert(&engine.Key{
		Device:         config.Device,
		Proxy:          config.ProxyURL,
		ProxyProcesses: config.Processes,
		LogLevel:       "info",
	})
	if err := engine.StartWithError(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proxyEngineRunning = true
	if userLog != nil {
		userLog.Printf("Proxy engine started: proxy=%s device=%s processes=%v", config.ProxyURL, config.Device, config.Processes)
	}
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if userLog != nil {
		userLog.Println("Proxy engine stopped by user")
	}
	proxyEngineRunning = false
	w.WriteHeader(http.StatusNoContent)
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

func main() {
	initLogger()
	if userLog != nil {
		userLog.Println("Application startup")
	}
	hideConsole()
	noBrowser := flag.Bool("no-browser", false, "Do not open browser on startup")
	flag.Parse()

	frontendRoot, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", http.FileServer(http.FS(frontendRoot)))
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/recognize", handleRecognize)
	http.HandleFunc("/proxy-config", handleProxyConfig)
	http.HandleFunc("/proxy-engine/status", handleProxyEngineStatus)
	http.HandleFunc("/proxy-engine/start", handleProxyEngineStart)
	http.HandleFunc("/proxy-engine/stop", handleProxyEngineStop)
	http.HandleFunc("/restart", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Restarting application...")
		if userLog != nil {
			userLog.Println("User action: Restarting application")
		}
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		os.Exit(0)
	})
	http.HandleFunc("/exit", func(w http.ResponseWriter, r *http.Request) {
		if userLog != nil {
			userLog.Println("User action: Exiting application")
		}
		os.Exit(0)
	})

	if !*noBrowser {
		go func() {
			time.Sleep(1 * time.Second)
			// Launch browser in app mode (Edge or Chrome)
			exec.Command("cmd", "/c", "start msedge --app=http://localhost:8006").Start()
		}()
	}

	fmt.Println("Server started at :8006")
	log.Fatal(http.ListenAndServe(":8006", nil))
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
