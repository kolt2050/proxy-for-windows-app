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

func (unsupportedResolver) Resolve(*M.Metadata) (string, error) {
	return "", fmt.Errorf("proxy-processes is supported only on Windows")
}
