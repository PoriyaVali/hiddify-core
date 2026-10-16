# Native-core handoff

## 2026-10-16 - Claude (cloud session) - anytls client weak-link fixes (BRANCH, NOT RELEASED)

Owner asked for the fixes made to the mihomo core's anytls client
(PoriyaVali/mihomo#2) to be applied to sing-box too.

Files: go.mod (one `replace` line), the hiddify-sing-box submodule pointer, and
this log. The work itself is in hiddify-sing-box `replace/sing-anytls`:
sing-anytls v0.0.13, vendored as its own unchanged commit, then patched. Its
README.dm.md lists each change and its evidence.

What changes for every anytls node:
- A FIN behind a slow upload no longer kills the session. The control frame
  waits for the write lock and gets a 30 s bound that counts only a holder
  making no progress; writes go out in 16 KiB chunks.
- The SYNACK watchdog follows the observed acknowledgement time (3-12 s), not
  a fixed 3 s.
- Session timings use the monotonic clock.
- Pool:
  - closed sessions are never pooled;
  - a request waiting on a handshake takes a session that joins the pool
    meanwhile;
  - a handshake its request no longer waits for (it gave up, or took a pooled
    session) goes on for up to 20 s and is pooled.
- TCP_NOTSENT_LOWAT 16 KiB on the socket.
- v0.0.13 itself also fixes a >64 KiB write corrupting the stream, FIN after
  pool return, and Close not unblocking stuck I/O.

Validation (Linux, this session):
- Unmodified v0.0.11 fails behavioural copies of three tests; the patched copy
  passes them.
- `go test` and `go test -race` pass on the vendored module.
- hiddify-core builds with the release tags and `-mod=readonly` for
  android/arm64, android/arm, linux/amd64 and windows/amd64.
- The Windows CI's `go test` set passes with the release tags.
- `go.sum` is unchanged.

Update, same day: the submodule now points at hiddify-sing-box b5f23bf9.
- 97468a87 fixes a Codex review finding (hiddify-sing-box#2). A request that
  took a pooled session left its own stalled handshake unbounded, because the
  20 s bound waited for the request's context, and sing-box's lives as long as
  the connection. A new test fails without the fix.
- b5f23bf9 records the weak-link bench in README.dm.md. Requests right after
  cancelled uploads on the bad link: 93.3% succeeded (196/210, 7 seeds)
  against 87.1% with v0.0.11. Counting failures, no percentile was slower.
  Browsing and downloads showed no difference beyond the spread between runs.
- Rebuilt with GOTOOLCHAIN=go1.25.6, -mod=readonly, the release tags and
  -checklinkname=0: ./cmd/main links for android/arm64, windows/amd64 and
  linux/amd64. For android/arm, which links only through cgo, the anytls and
  libbox packages compile.

NOT done: gomobile bind (no NDK here; the app's CI builds it), and any phone
test.

## 2026-09-07 - Codex - 1.9.5 field follow-up (UNCOMMITTED / NOT RELEASED)

Owner confirms failures on 1.9.5. Runtime config has Wi-Fi binding and the four
TCP transports, while dns-direct still times out. Windows-only builder now
races UDP and TCP for every supplied physical resolver; the parent also sends
DHCP DNS so DIRECT no longer depends entirely on four public TCP/53 services.
Files: v2/config/windows_tun_options.go, windows_tun_options_test.go, this log.
Strict routing and rule precedence unchanged. Tests updated, NOT YET RUN at
this checkpoint. No live probe/reconnect or Windows firewall/route change.
This does not prove the remaining DIRECT re-entry symptom is fixed.

Follow-up validation: native config tests PASS with release Windows tags and
-mod=readonly / -ldflags=-checklinkname=0. Parent Flutter suite 492 passed,
1 skipped; analyzer exit 0. This follow-up has no native Android changes.
Desktop Windows c-shared compilation also PASSED (42,180,608-byte DLL), staged
in an owned temp directory and not installed/loaded. Source ready for commit;
parent handoff will record the actual commit/push state. No release/tag moved.

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
