//go:build !windows

package router

import (
	"fmt"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

type unsupportedResolver struct{}

func newProcessResolver() (processResolver, error) {
	return nil, fmt.Errorf("proxy-processes is supported only on Windows")
}

func (unsupportedResolver) Resolve(*M.Metadata) (OwnerInfo, error) {
	return OwnerInfo{}, fmt.Errorf("proxy-processes is supported only on Windows")
}

func parentPID(uint32) (uint32, error) {
	return 0, fmt.Errorf("process ancestry is supported only on Windows")
}
