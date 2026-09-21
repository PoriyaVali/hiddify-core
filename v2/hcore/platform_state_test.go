package hcore

import (
	"sync"
	"testing"

	"google.golang.org/grpc"
)

func TestPlatformSurvivesForegroundReattach(t *testing.T) {
	var state platformState
	state.configure(nil) // cold Activity
	if ctx, platform := state.snapshot(); ctx == nil || platform != nil {
		t.Fatal("cold foreground must have a context but no VPN callback")
	}
	vpn := &MobilePlatformInterface{}
	state.configure(vpn)
	ctx, _ := state.snapshot()
	for range 3 {
		state.configure(nil) // Activity background/resume, with VPN still running
		current, platform := state.snapshot()
		if current != ctx || platform != vpn {
			t.Fatal("foreground reattach erased the VPN platform/context needed by restart")
		}
	}
	replacement := &MobilePlatformInterface{}
	state.configure(replacement)
	if _, platform := state.snapshot(); platform != replacement {
		t.Fatal("new VPN service must replace the old callback")
	}
	state.clear() // actual VPN server teardown, not Activity detach
	state.configure(nil)
	if ctx, platform := state.snapshot(); ctx == nil || platform != nil {
		t.Fatal("VPN teardown retained a stale Android service")
	}
}

func TestOnlyBackgroundServerCloseReleasesPlatform(t *testing.T) {
	previousStatic, previousServers := static, grpcServer
	static = &HiddifyInstance{}
	grpcServer = map[SetupMode]*grpc.Server{
		SetupMode_GRPC_NORMAL_INSECURE:     grpc.NewServer(),
		SetupMode_GRPC_BACKGROUND_INSECURE: grpc.NewServer(),
	}
	t.Cleanup(func() {
		for _, server := range grpcServer {
			server.Stop()
		}
		static, grpcServer = previousStatic, previousServers
	})
	vpn := &MobilePlatformInterface{}
	static.platform.configure(vpn)
	CloseGrpcServer(SetupMode_GRPC_NORMAL_INSECURE)
	static.platform.configure(nil) // foreground setup after resume
	if _, platform := static.platform.snapshot(); platform != vpn {
		t.Fatal("Activity detach/resume cleared the running VPN binding")
	}
	CloseGrpcServer(SetupMode_GRPC_BACKGROUND_INSECURE)
	if _, platform := static.platform.snapshot(); platform != nil {
		t.Fatal("background server teardown retained the service callback")
	}
}

func TestPlatformConcurrentForegroundAndSnapshot(t *testing.T) {
	var state platformState
	vpn := &MobilePlatformInterface{}
	state.configure(vpn)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				state.configure(nil)
				if ctx, platform := state.snapshot(); ctx == nil || platform != vpn {
					t.Error("lost VPN binding during concurrent foreground attach")
					return
				}
			}
		}()
	}
	wg.Wait()
}
