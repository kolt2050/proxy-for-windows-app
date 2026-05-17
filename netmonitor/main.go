package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/windows"
)

func main() {
	filterName := flag.String("name", "", "Filter by process name (e.g. chrome.exe)")
	filterPID := flag.Uint("pid", 0, "Filter by PID")
	interval := flag.Duration("interval", 1*time.Second, "Update interval")
	flag.Parse()

	fmt.Printf("Monitoring connections (Update every %v)...\n", *interval)
	if *filterName != "" {
		fmt.Printf("Filtering by Name: %s\n", *filterName)
	}
	if *filterPID != 0 {
		fmt.Printf("Filtering by PID: %d\n", *filterPID)
	}
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	for {
		// Clear screen (ANSI)
		fmt.Print("\033[H\033[2J")
		fmt.Fprintf(w, "PROTO\tPROCESS\tPID\tLOCAL ADDRESS\tREMOTE ADDRESS\tSTATE\n")

		// TCP
		tcpRows, err := getTCPTable()
		if err == nil {
			for _, row := range tcpRows {
				if shouldSkip(row.OwningPid, *filterPID, *filterName) {
					continue
				}
				local := fmt.Sprintf("%s:%d", formatIP(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort)))
				remote := fmt.Sprintf("%s:%d", formatIP(row.RemoteAddr), windows.Ntohs(uint16(row.RemotePort)))
				state := tcpState(row.State)
				fmt.Fprintf(w, "TCP\t%s\t%d\t%s\t%s\t%s\n", getProcessName(row.OwningPid), row.OwningPid, local, remote, state)
			}
		}

		// UDP
		udpRows, err := getUDPTable()
		if err == nil {
			for _, row := range udpRows {
				if shouldSkip(row.OwningPid, *filterPID, *filterName) {
					continue
				}
				local := fmt.Sprintf("%s:%d", formatIP(row.LocalAddr), windows.Ntohs(uint16(row.LocalPort)))
				fmt.Fprintf(w, "UDP\t%s\t%d\t%s\t*\t-\n", getProcessName(row.OwningPid), row.OwningPid, local)
			}
		}

		w.Flush()
		time.Sleep(*interval)
	}
}

func shouldSkip(pid uint32, filterPID uint, filterName string) bool {
	if filterPID != 0 && uint32(filterPID) != pid {
		return true
	}
	if filterName != "" {
		name := strings.ToLower(getProcessName(pid))
		if !strings.Contains(name, strings.ToLower(filterName)) {
			return true
		}
	}
	return false
}

func tcpState(s uint32) string {
	states := map[uint32]string{
		1:  "CLOSED",
		2:  "LISTEN",
		3:  "SYN_SENT",
		4:  "SYN_RCVD",
		5:  "ESTAB",
		6:  "FIN_WAIT1",
		7:  "FIN_WAIT2",
		8:  "CLOSE_WAIT",
		9:  "CLOSING",
		10: "LAST_ACK",
		11: "TIME_WAIT",
		12: "DELETE_TCB",
	}
	if v, ok := states[s]; ok {
		return v
	}
	return fmt.Sprintf("UNKNOWN(%d)", s)
}
