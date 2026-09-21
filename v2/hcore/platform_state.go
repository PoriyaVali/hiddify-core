package hcore

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/experimental/libbox"
)

// Foreground and VPN gRPC servers share a Go runtime on Android. The Activity
// supplies no platform callback; that must not erase the live VPN's callback.
type platformState struct {
	mu       sync.RWMutex
	ctx      context.Context
	platform libbox.PlatformInterface
}

func (s *platformState) configure(platform libbox.PlatformInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if platform == nil && s.ctx != nil {
		return // Activity reattachment is not VPN teardown.
	}
	s.ctx = libbox.BaseContext(platform)
	s.platform = platform
}

func (s *platformState) snapshot() (context.Context, libbox.PlatformInterface) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ctx, s.platform
}

func (s *platformState) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = libbox.BaseContext(nil)
	s.platform = nil
}
