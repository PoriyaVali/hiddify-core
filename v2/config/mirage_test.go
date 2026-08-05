package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

// realityOutbound builds a VLESS outbound using REALITY, the case the old
// TLSTricks patch deliberately skipped and the one Mirage exists for.
func realityOutbound() option.Outbound {
	return option.Outbound{
		Type: C.TypeVLESS,
		Tag:  "node",
		Options: &option.VLESSOutboundOptions{
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "www.microsoft.com",
					Reality:    &option.OutboundRealityOptions{Enabled: true},
				},
			},
		},
	}
}

// TestMirageReachesRealityOutbound is the wiring test that matters: the option
// has to survive being written through TakeOutboundTLSOptions. If that returned
// a copy the flag would be silently dropped and every node would go out
// unfragmented while the setting still read as on.
func TestMirageReachesRealityOutbound(t *testing.T) {
	t.Parallel()
	opt := HiddifyOptions{Mirage: MirageOptions{Enable: true, Offset: 7}}

	out := patchOutboundMirage(realityOutbound(), opt)

	tls := out.Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
	require.True(t, tls.Mirage, "mirage must be set on a REALITY outbound")
	require.Equal(t, 7, tls.MirageOffset)
}

func TestMirageDisabledLeavesOutboundAlone(t *testing.T) {
	t.Parallel()
	out := patchOutboundMirage(realityOutbound(), HiddifyOptions{})

	tls := out.Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
	require.False(t, tls.Mirage)
}

// TestMirageSkipsNonTLS guards against setting the flag on outbounds that have
// no TLS at all (selectors, direct, block...), which would be meaningless.
func TestMirageSkipsNonTLS(t *testing.T) {
	t.Parallel()
	opt := HiddifyOptions{Mirage: MirageOptions{Enable: true}}

	for _, typ := range []string{C.TypeSelector, C.TypeDirect, C.TypeBlock, C.TypeDNS} {
		out := patchOutboundMirage(option.Outbound{Type: typ, Tag: typ}, opt)
		require.Equal(t, typ, out.Type)
	}
}

// TestMirageDefaultOn documents that shipping defaults turn Mirage on.
func TestMirageDefaultOn(t *testing.T) {
	t.Parallel()
	require.True(t, DefaultHiddifyOptions().Mirage.Enable)
}
