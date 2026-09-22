package tunnelservice

import "testing"

func TestTunnelServiceAddressUsesARealPort(t *testing.T) {
	if tunnelServiceAddress != "127.0.0.1:18020" {
		t.Fatalf("invalid tunnel service endpoint: %q", tunnelServiceAddress)
	}
}

func TestDesktopAppTrafficIsExcludedFromTunnel(t *testing.T) {
	config := makeTunnelConfig(&TunnelStartRequest{ServerPort: 12334})
	for _, rule := range config.Route.Rules {
		for _, name := range rule.DefaultOptions.ProcessName {
			if name == "Doctor Mobile.exe" && rule.DefaultOptions.RouteOptions.Outbound == "direct-out" {
				return
			}
		}
	}
	t.Fatal("Doctor Mobile.exe can be routed back into its own SOCKS tunnel")
}
