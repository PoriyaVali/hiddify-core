package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// The app's "TLS tricks -> fragment" switch and the "direct with fragment"
// routing rule both end in the dialer option `tls_fragment`. The sing-box fork
// declared that option but never read it, so for a long time both went out
// unfragmented while the settings read as on. This test follows the whole
// path the app uses: the app's settings JSON -> the final config -> JSON, as
// libbox receives it -> sing-box's dialer -> bytes on a TCP socket.
func TestTLSFragmentReachesTheWire(t *testing.T) {
	t.Parallel()
	hopts := DefaultHiddifyOptions()
	require.NoError(t, json.Unmarshal([]byte(`{"tls-tricks":{"enable-fragment":true,"fragment-size":"10-30","fragment-sleep":"1-2"}}`), hopts))
	input := &ReadOptions{Options: &option.Options{Outbounds: []option.Outbound{{
		Type: C.TypeVLESS,
		Tag:  "node",
		Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 443},
			UUID:          "bf000d23-0752-40b4-affe-68f7707a9661",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "cdn.example.com"},
			},
			Transport: &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket},
		},
	}}}}
	ctx := libbox.BaseContext(nil)
	built, err := BuildConfig(ctx, hopts, input)
	require.NoError(t, err)
	data, err := built.MarshalJSONContext(ctx)
	require.NoError(t, err)
	final, err := singjson.UnmarshalExtendedContext[option.Options](ctx, data)
	require.NoError(t, err)

	dialers := map[string]option.DialerOptions{}
	for _, outbound := range final.Outbounds {
		if wrapper, ok := outbound.Options.(option.DialerOptionsWrapper); ok {
			dialers[outbound.Tag] = wrapper.TakeDialerOptions()
		}
	}
	hello := testClientHello(t)
	for _, tag := range []string{OutboundDirectFragmentTag, "node"} {
		options, ok := dialers[tag]
		require.True(t, ok, "%s is missing from the final config", tag)
		require.True(t, options.TLSFragment.Enabled, "%s lost tls_fragment", tag)

		records := dialAndCollectRecords(t, options, hello)
		require.Greater(t, len(records), 5, "%s: the ClientHello reached the server in %d record(s)", tag, len(records))
		var payload []byte
		for _, r := range records {
			require.LessOrEqual(t, len(r), 30, "%s: a record is larger than fragment-size", tag)
			payload = append(payload, r...)
		}
		require.Equal(t, hello[5:], payload, "%s: the server cannot reassemble the ClientHello", tag)
	}

	// The plain direct outbound must stay untouched.
	records := dialAndCollectRecords(t, dialers[OutboundDirectTag], hello)
	require.Len(t, records, 1, "the plain direct outbound was fragmented")
}

func dialAndCollectRecords(t *testing.T, options option.DialerOptions, hello []byte) [][]byte {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		data, _ := io.ReadAll(conn)
		received <- data
	}()
	outboundDialer, err := dialer.New(libbox.BaseContext(nil), options, false)
	require.NoError(t, err)
	conn, err := outboundDialer.DialContext(context.Background(), "tcp", M.SocksaddrFromNet(listener.Addr()))
	require.NoError(t, err)
	_, err = conn.Write(hello)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	stream := <-received
	var records [][]byte
	for len(stream) > 0 {
		require.GreaterOrEqual(t, len(stream), 5)
		require.Equal(t, byte(0x16), stream[0])
		n := int(stream[3])<<8 | int(stream[4])
		require.GreaterOrEqual(t, len(stream), 5+n)
		records = append(records, stream[5:5+n])
		stream = stream[5+n:]
	}
	return records
}

type helloCapture struct {
	net.Conn
	mu    sync.Mutex
	first []byte
}

func (c *helloCapture) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.first == nil {
		c.first = bytes.Clone(b)
	}
	return len(b), nil
}

func (c *helloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *helloCapture) Close() error                     { return nil }
func (c *helloCapture) SetDeadline(time.Time) error      { return nil }
func (c *helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (c *helloCapture) SetWriteDeadline(time.Time) error { return nil }

func testClientHello(t *testing.T) []byte {
	t.Helper()
	capture := &helloCapture{}
	_ = tls.Client(capture, &tls.Config{ServerName: "www.example.com"}).Handshake()
	require.NotEmpty(t, capture.first)
	return capture.first
}

// patchOutboundTLSTricks used value-type assertions that never match sing-box's
// pointer options, so it returned early on every real node.
func TestTLSTricksReachPointerOutbounds(t *testing.T) {
	t.Parallel()
	hopts := HiddifyOptions{TLSTricks: TLSTricks{EnableFragment: true, FragmentSize: "10-30", FragmentSleep: "2-8", MixedSNICase: true}}
	tlsOptions := func() option.OutboundTLSOptionsContainer {
		return option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "cdn.example.com"}}
	}
	ws := &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket}
	for _, outbound := range []option.Outbound{
		{Type: C.TypeVLESS, Tag: "vless", Options: &option.VLESSOutboundOptions{OutboundTLSOptionsContainer: tlsOptions(), Transport: ws}},
		{Type: C.TypeTrojan, Tag: "trojan", Options: &option.TrojanOutboundOptions{OutboundTLSOptionsContainer: tlsOptions(), Transport: ws}},
		{Type: C.TypeVMess, Tag: "vmess", Options: &option.VMessOutboundOptions{OutboundTLSOptionsContainer: tlsOptions(), Transport: ws}},
	} {
		out := patchOutboundTLSTricks(outbound, hopts)
		dialerOptions := out.Options.(option.DialerOptionsWrapper).TakeDialerOptions()
		require.True(t, dialerOptions.TLSFragment.Enabled, outbound.Tag)
		require.Equal(t, "10-30", dialerOptions.TLSFragment.Size, outbound.Tag)
		tls := out.Options.(option.OutboundTLSOptionsWrapper).TakeOutboundTLSOptions()
		require.NotNil(t, tls.TLSTricks, outbound.Tag)
		require.True(t, tls.TLSTricks.MixedCaseSNI, outbound.Tag)
	}
	// Outside the tricks' scope (no websocket/gRPC/HTTPUpgrade): untouched.
	plain := option.Outbound{Type: C.TypeVLESS, Tag: "tcp", Options: &option.VLESSOutboundOptions{OutboundTLSOptionsContainer: tlsOptions()}}
	out := patchOutboundTLSTricks(plain, hopts)
	require.False(t, out.Options.(option.DialerOptionsWrapper).TakeDialerOptions().TLSFragment.Enabled)
}

// The app's transfer-check block reaches the sing-box monitor; without it the
// check stays off.
func TestTransferCheckReachesTheMonitor(t *testing.T) {
	t.Parallel()
	hopts := DefaultHiddifyOptions()
	require.NoError(t, json.Unmarshal([]byte(`{"transfer-check":{"enable":true,"endpoints":["https://ddr.example/dm-transfer-v1.php"]}}`), hopts))
	ctx := libbox.BaseContext(nil)
	built, err := BuildConfig(ctx, hopts, &ReadOptions{Options: &option.Options{Outbounds: []option.Outbound{{
		Type: C.TypeSOCKS, Tag: "node", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 1080}},
	}}}})
	require.NoError(t, err)
	require.NotNil(t, built.Experimental)
	require.NotNil(t, built.Experimental.Monitoring)
	check := built.Experimental.Monitoring.TransferCheck
	require.NotNil(t, check)
	require.True(t, check.Enabled)
	require.Equal(t, []string{"https://ddr.example/dm-transfer-v1.php"}, check.Endpoints)

	off, err := BuildConfig(ctx, DefaultHiddifyOptions(), &ReadOptions{Options: &option.Options{Outbounds: []option.Outbound{{
		Type: C.TypeSOCKS, Tag: "node", Options: &option.SOCKSOutboundOptions{ServerOptions: option.ServerOptions{Server: "192.0.2.1", ServerPort: 1080}},
	}}}})
	require.NoError(t, err)
	if off.Experimental != nil && off.Experimental.Monitoring != nil && off.Experimental.Monitoring.TransferCheck != nil {
		require.False(t, off.Experimental.Monitoring.TransferCheck.Enabled)
	}
}
