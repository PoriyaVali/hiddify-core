# Native-core handoff

## 2026-09-07 - Codex - Windows runtime egress for Doctor Mobile 1.9.5

Base: clean doctormobile d7988e3; dm/doctormobile matched. Requested by the
owner as part of Windows bypass/DNS repairs and app 1.9.5 Android/Windows builds.

Files: v2/config/hiddify_option.go, builder.go, windows_tun_options.go,
windows_tun_options_test.go, go.mod, AI_HANDOFF.md.

Added runtime-only windows-tun settings and apply them after the normal config
builder, only when C.IsWindows && EnableTun. Pin the chosen pre-TUN physical NIC,
replace the client-selected legacy direct-DNS default with parallel regional
TCP transports, preserve the dns-direct tag and strict route protection.
Conservatively lift only literal, unconditional direct IPv4 rules that win
against every earlier possible proxy/reject/conditional rule. Never substitute
another core's country CIDR file for the actual sing-box rule-set. Do not lift
fragmented direct rules; preserve their transport behavior.

Validation: go test ./v2/config passes with Windows release tags and
-ldflags=-checklinkname=0, including final BuildConfig wiring and earlier-rule
precedence cases. Initial go test requested go.mod updates: recorded testify
1.11.1 plus its two indirect dependencies at their already-resolved versions.
No other dependency upgrade. Desktop Windows c-shared compilation PASSED with
the release tags/-trimpath/-checklinkname=0; emitted a 42,180,096-byte DLL in an
owned temp directory (not installed or loaded). No live VPN, route mutation,
reconnection or leak tests authorized.

Status: uncommitted at this checkpoint, not released. Parent app supplies the
snapshot and must reference this commit before building; its Windows CI cache
must include native sources. Android release artifacts remain 4.1.4, untouched.
The physical NIC snapshot is refreshed on reconnect. Actual field confirmation
is still required; static/unit tests do not prove the reported network loop is
gone. The parent repository AI_HANDOFF.md is the full session record.
