package config

import (
	"net"
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

// The probe must say what the stack can do, not whether "::1" parses.
func TestIPv6ProbeMatchesTheStack(t *testing.T) {
	if C.IsIos || C.IsDarwin {
		t.Skip("assumed supported there")
	}
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		ln.Close()
	}
	require.Equal(t, err == nil, isIPv6Supported(), "listening on [::1] gave %v", err)
}

func mixedListens(t *testing.T, options *option.Options) []string {
	t.Helper()
	var binds []string
	for _, inbound := range options.Inbounds {
		if inbound.Type != C.TypeMixed {
			continue
		}
		opts, ok := inbound.Options.(*option.HTTPMixedInboundOptions)
		require.True(t, ok)
		binds = append(binds, opts.Listen.Build(netip.Addr{}).String())
	}
	return binds
}

func TestWithoutIPv6TheLocalProxyListensOnIPv4Only(t *testing.T) {
	old := ipv6Supported
	t.Cleanup(func() { ipv6Supported = old })

	ipv6Supported = func() bool { return false }
	for _, lan := range []bool{false, true} {
		options := &option.Options{}
		hopt := DefaultHiddifyOptions()
		hopt.MixedPort = 12334
		hopt.AllowConnectionFromLAN = lan
		setInbound(options, hopt)
		want := []string{"127.0.0.1"}
		if lan {
			want = []string{"0.0.0.0"}
		}
		require.Equal(t, want, mixedListens(t, options), "LAN access %v", lan)
	}

	ipv6Supported = func() bool { return true }
	options := &option.Options{}
	hopt := DefaultHiddifyOptions()
	hopt.MixedPort = 12334
	setInbound(options, hopt)
	require.Equal(t, []string{"::1", "127.0.0.1"}, mixedListens(t, options))
}
