package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procGetExtendedTcpTable        = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable        = modiphlpapi.NewProc("GetExtendedUdpTable")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
	procGetConsoleWindow           = modkernel32.NewProc("GetConsoleWindow")
	moduser32                    = windows.NewLazySystemDLL("user32.dll")
	procShowWindow                 = moduser32.NewProc("ShowWindow")
)

const (
	SW_HIDE = 0
)

const (
	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1
)

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MIB_TCPTABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_TCPROW_OWNER_PID
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type MIB_UDPTABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_UDPROW_OWNER_PID
}

type MIB_TCP6ROW_OWNER_PID struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

type MIB_TCP6TABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_TCP6ROW_OWNER_PID
}

type MIB_UDP6ROW_OWNER_PID struct {
	LocalAddr    [16]byte
	LocalScopeId uint32
	LocalPort    uint32
	OwningPid    uint32
}

type MIB_UDP6TABLE_OWNER_PID struct {
	NumEntries uint32
	Table      [1]MIB_UDP6ROW_OWNER_PID
}

func getTCPTable() ([]MIB_TCPROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), TCP_TABLE_OWNER_PID_ALL, 0)
	if size == 0 { return nil, nil }
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), TCP_TABLE_OWNER_PID_ALL, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}
	table := (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	if table.NumEntries == 0 { return nil, nil }
	return (*[1 << 20]MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func getTCP6Table() ([]MIB_TCP6ROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET6), TCP_TABLE_OWNER_PID_ALL, 0)
	if size == 0 { return nil, nil }
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET6), TCP_TABLE_OWNER_PID_ALL, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcp6Table failed: %d", ret)
	}
	table := (*MIB_TCP6TABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	if table.NumEntries == 0 { return nil, nil }
	return (*[1 << 20]MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func getUDPTable() ([]MIB_UDPROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), UDP_TABLE_OWNER_PID, 0)
	if size == 0 { return nil, nil }
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), UDP_TABLE_OWNER_PID, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}
	table := (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	if table.NumEntries == 0 { return nil, nil }
	return (*[1 << 20]MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func getUDP6Table() ([]MIB_UDP6ROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET6), UDP_TABLE_OWNER_PID, 0)
	if size == 0 { return nil, nil }
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET6), UDP_TABLE_OWNER_PID, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdp6Table failed: %d", ret)
	}
	table := (*MIB_UDP6TABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	if table.NumEntries == 0 { return nil, nil }
	return (*[1 << 20]MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func getProcessName(pid uint32) string {
	if pid == 0 {
		return "System Idle Process"
	}
	if pid == 4 {
		return "System"
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		// Fallback: try to see if it's a known system PID or just handle the error
		return fmt.Sprintf("Unknown (PID %d)", pid)
	}
	defer windows.CloseHandle(handle)
	var size uint32 = windows.MAX_PATH
	buf := make([]uint16, size)
	ret, _, _ := procQueryFullProcessImageNameW.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "Access Denied"
	}
	fullPath := syscall.UTF16ToString(buf[:size])
	for i := len(fullPath) - 1; i >= 0; i-- {
		if fullPath[i] == '\\' || fullPath[i] == '/' {
			return fullPath[i+1:]
		}
	}
	return fullPath
}

func formatIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func formatIP6(ip [16]byte) string {
	return fmt.Sprintf("[%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

func hideConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, SW_HIDE)
}
