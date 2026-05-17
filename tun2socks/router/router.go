package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

type processResolver interface {
	Resolve(metadata *M.Metadata) (OwnerInfo, error)
}

type OwnerInfo struct {
	PID         uint32
	ProcessName string
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
	owner, err := r.resolver.Resolve(metadata)
	if err != nil {
		log.Debugf("[ROUTER] %s %s -> %s: direct (process unresolved: %v)",
			metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), err)
		return r.direct
	}
	if _, ok := r.targets[strings.ToLower(owner.ProcessName)]; ok {
		log.Infof("[ROUTER] %s %s -> %s: proxy (%s)",
			metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), owner.ProcessName)
		return r.proxied
	}
	log.Debugf("[ROUTER] %s %s -> %s: direct (%s)",
		metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), owner.ProcessName)
	return r.direct
}

type PIDRouter struct {
	direct   proxy.Proxy
	resolver processResolver
	mu       sync.RWMutex
	targets  map[uint32]proxy.Proxy
	labels   map[uint32]string
}

func NewPIDRouter(direct proxy.Proxy) (*PIDRouter, error) {
	resolver, err := newProcessResolver()
	if err != nil {
		return nil, err
	}
	return &PIDRouter{
		direct:   direct,
		resolver: resolver,
		targets:  make(map[uint32]proxy.Proxy),
		labels:   make(map[uint32]string),
	}, nil
}

func (r *PIDRouter) Set(pid uint32, proxied proxy.Proxy, label string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[pid] = proxied
	r.labels[pid] = label
}

func (r *PIDRouter) Delete(pid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targets, pid)
	delete(r.labels, pid)
}

func (r *PIDRouter) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	return r.pick(metadata).DialContext(ctx, metadata)
}

func (r *PIDRouter) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	return r.pick(metadata).DialUDP(metadata)
}

func (r *PIDRouter) pick(metadata *M.Metadata) proxy.Proxy {
	owner, err := r.resolver.Resolve(metadata)
	if err != nil {
		log.Debugf("[ROUTER] %s %s -> %s: direct (process unresolved: %v)",
			metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), err)
		return r.direct
	}

	r.mu.RLock()
	proxied, ok := r.targets[owner.PID]
	label := r.labels[owner.PID]
	r.mu.RUnlock()
	if ok {
		log.Infof("[ROUTER] %s %s -> %s: proxy pid=%d process=%s rule=%s",
			metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), owner.PID, owner.ProcessName, label)
		return proxied
	}

	currentPID := owner.PID
	for depth := 0; depth < 12; depth++ {
		parent, parentErr := parentPID(currentPID)
		if parentErr != nil || parent == 0 || parent == currentPID {
			break
		}
		r.mu.RLock()
		proxied, ok = r.targets[parent]
		label = r.labels[parent]
		r.mu.RUnlock()
		if ok {
			log.Infof("[ROUTER] %s %s -> %s: proxy pid=%d process=%s inherited-from=%d rule=%s",
				metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), owner.PID, owner.ProcessName, parent, label)
			return proxied
		}
		currentPID = parent
	}

	log.Debugf("[ROUTER] %s %s -> %s: direct pid=%d process=%s",
		metadata.Network, metadata.SourceAddress(), metadata.DestinationAddress(), owner.PID, owner.ProcessName)
	return r.direct
}
