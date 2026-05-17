package router

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

type processResolver interface {
	Resolve(metadata *M.Metadata) (string, error)
}

type processRouter struct {
	proxied  proxy.Proxy
	direct   proxy.Proxy
	targets  map[string]struct{}
	resolver processResolver
}

func NewProcessRouter(proxied, direct proxy.Proxy, processNames []string) (proxy.Proxy, error) {
	resolver, err := newProcessResolver()
	if err != nil {
		return nil, err
	}

	targets := make(map[string]struct{}, len(processNames))
	for _, processName := range processNames {
		normalized := strings.ToLower(strings.TrimSpace(processName))
		if normalized == "" {
			continue
		}
		targets[normalized] = struct{}{}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("proxy-processes contains no valid process names")
	}

	return &processRouter{
		proxied:  proxied,
		direct:   direct,
		targets:  targets,
		resolver: resolver,
	}, nil
}

func (r *processRouter) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	return r.pick(metadata).DialContext(ctx, metadata)
}

func (r *processRouter) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	return r.pick(metadata).DialUDP(metadata)
}

func (r *processRouter) pick(metadata *M.Metadata) proxy.Proxy {
	processName, err := r.resolver.Resolve(metadata)
	if err != nil {
		log.Debugf("[ROUTER] %s %s -> %s: direct (process unresolved: %v)",
			metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), err)
		return r.direct
	}
	if _, ok := r.targets[strings.ToLower(processName)]; ok {
		log.Infof("[ROUTER] %s %s -> %s: proxy (%s)",
			metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), processName)
		return r.proxied
	}
	log.Debugf("[ROUTER] %s %s -> %s: direct (%s)",
		metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), processName)
	return r.direct
}
