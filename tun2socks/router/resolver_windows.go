//go:build windows

package router

import (
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

var (
	modIphlpapi                   = windows.NewLazySystemDLL("iphlpapi.dll")
	modKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procGetExtendedTcpTable       = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable       = modIphlpapi.NewProc("GetExtendedUdpTable")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
)

type windowsResolver struct{}

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCPTableOwnerPID struct {
	NumEntries uint32
	Table      [1]mibTCPRowOwnerPID
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type mibUDPTableOwnerPID struct {
	NumEntries uint32
	Table      [1]mibUDPRowOwnerPID
}

func newProcessResolver() (processResolver, error) {
	return windowsResolver{}, nil
}

func (windowsResolver) Resolve(metadata *M.Metadata) (OwnerInfo, error) {
	switch metadata.Network {
	case M.TCP:
		pid, err := findTCPPID(metadata)
		if err != nil {
			return OwnerInfo{}, err
		}
		name, err := processName(pid)
		if err != nil {
			return OwnerInfo{}, err
		}
		return OwnerInfo{PID: pid, ProcessName: name}, nil
	case M.UDP:
		pid, err := findUDPPID(metadata)
		if err != nil {
			return OwnerInfo{}, err
		}
		name, err := processName(pid)
		if err != nil {
			return OwnerInfo{}, err
		}
		return OwnerInfo{PID: pid, ProcessName: name}, nil
	default:
		return OwnerInfo{}, fmt.Errorf("unsupported network: %s", metadata.Network)
	}
}

func findTCPPID(metadata *M.Metadata) (uint32, error) {
	rows, err := tcpRows()
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if windows.Ntohs(uint16(row.LocalPort)) != metadata.SrcPort {
			continue
		}
		if windows.Ntohs(uint16(row.RemotePort)) != metadata.DstPort {
			continue
		}
		if !sameIPv4(row.LocalAddr, metadata.SrcIP) || !sameIPv4(row.RemoteAddr, metadata.DstIP) {
			continue
		}
		return row.OwningPID, nil
	}
	return 0, fmt.Errorf("tcp owner not found for %s -> %s", metadata.SourceAddress(), metadata.DestinationAddress())
}

func findUDPPID(metadata *M.Metadata) (uint32, error) {
	rows, err := udpRows()
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		if windows.Ntohs(uint16(row.LocalPort)) != metadata.SrcPort {
			continue
		}
		if !sameIPv4(row.LocalAddr, metadata.SrcIP) {
			continue
		}
		return row.OwningPID, nil
	}
	return 0, fmt.Errorf("udp owner not found for %s", metadata.SourceAddress())
}

func tcpRows() ([]mibTCPRowOwnerPID, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), tcpTableOwnerPIDAll, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}
	table := (*mibTCPTableOwnerPID)(unsafe.Pointer(&buf[0]))
	if table.NumEntries == 0 {
		return nil, nil
	}
	return (*[1 << 20]mibTCPRowOwnerPID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func udpRows() ([]mibUDPRowOwnerPID, error) {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), udpTableOwnerPID, 0)
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, uintptr(windows.AF_INET), udpTableOwnerPID, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}
	table := (*mibUDPTableOwnerPID)(unsafe.Pointer(&buf[0]))
	if table.NumEntries == 0 {
		return nil, nil
	}
	return (*[1 << 20]mibUDPRowOwnerPID)(unsafe.Pointer(&table.Table))[:table.NumEntries:table.NumEntries], nil
}

func processName(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	size := uint32(windows.MAX_PATH)
	buf := make([]uint16, size)
	ret, _, callErr := procQueryFullProcessImageName.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", callErr
	}
	fullPath := syscall.UTF16ToString(buf[:size])
	idx := strings.LastIndexAny(fullPath, `\/`)
	if idx >= 0 {
		return fullPath[idx+1:], nil
	}
	return fullPath, nil
}

func parentPID(pid uint32) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0, err
	}
	for {
		if entry.ProcessID == pid {
			return entry.ParentProcessID, nil
		}
		err := windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return 0, fmt.Errorf("parent process not found for pid=%d", pid)
}

func sameIPv4(raw uint32, ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	addr := ip.As4()
	return raw == uint32(addr[0])|uint32(addr[1])<<8|uint32(addr[2])<<16|uint32(addr[3])<<24
}
