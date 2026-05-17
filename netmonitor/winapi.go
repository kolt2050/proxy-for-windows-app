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

func getTCPTable() ([]MIB_TCPROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), TCP_TABLE_OWNER_PID_ALL, 0)
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), TCP_TABLE_OWNER_PID_ALL, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}
	table := (*MIB_TCPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	return (*[1 << 20]MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func getUDPTable() ([]MIB_UDPROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), UDP_TABLE_OWNER_PID, 0)
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), UDP_TABLE_OWNER_PID, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}
	table := (*MIB_UDPTABLE_OWNER_PID)(unsafe.Pointer(&buf[0]))
	return (*[1 << 20]MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func getProcessName(pid uint32) string {
	if pid == 0 {
		return "System"
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "Unknown"
	}
	defer windows.CloseHandle(handle)
	var size uint32 = windows.MAX_PATH
	buf := make([]uint16, size)
	ret, _, _ := procQueryFullProcessImageNameW.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ret == 0 {
		return "Unknown"
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
