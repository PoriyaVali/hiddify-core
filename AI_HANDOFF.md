# Native-core handoff

## 2026-10-16 - Codex - Doctor Mobile 2.2.3 integration validation (IN PROGRESS, NOT RELEASED)

Final integration checkpoint before commit: minimal MVS refresh succeeded,
then `go test -mod=readonly` with all release tags and
`-ldflags=-checklinkname=0 ./...` PASSED on final sing-box pointer 76e4f8d5.
go.mod updates are the versions required by that merged module (sing 0.8.14,
sing-tun 0.8.15, sing-quic 0.6.5, wireguard 0.0.4 and its indirect graph),
not an unconstrained tidy or dependency upgrade. go.sum adds 38 checksums.
Final release-tag Windows c-shared build PASSED (42,377,728-byte DLL),
Android arm64 CLI built and mobile/libbox compile is finishing, Linux amd64
CLI build PASSED. Race-enabled full core suite is running, not claimed yet.
Fixture and go.mod/go.sum source diff reviewed; `git diff --check` passed.

Mihomo v1.19.32-dm3 release is now public with all 10 expected ABI/platform
assets. All Android and Desktop/OpenWRT build jobs passed; final release job
and downloaded-asset checks are being confirmed. The app must use dm3 rather
than dm2. No Doctor Mobile app release has been published by this agent.

Checkpoint update: GitHub confirms Mihomo PR4 merged at
5dcbf0b34f64c5927e089aa5e68eff553efa384b; tag v1.19.32-dm3 was created
and pushed there. Android tag run 38951834813 and Desktop/OpenWRT run
38951834343 are running; assets are NOT yet verified or claimed published.
Sing-box PR2 merged at 76e4f8d548763167656138db749ad122ec3abebb. Its tree
6b44c21d778303d4c3ac7b1134f1d90b37b4788b exactly matches the tested local
merge preview with newer main f3a43bea. All 115 release cmd/libbox graph
module packages passed excluding pre-existing TestHosts, whose system-hosts
assumption fails on this Windows machine; its fixed-file assertion passed in
the complete attempt. Release-tag Windows executable build passed. Expanded
`./...` still fails in unshipped tailscale/derp/oomkiller packages, unchanged
by this merge; this is recorded, not hidden as a passing complete suite.

The new deterministic profile fixture PASSED, then the complete hiddify-core
release-tag suite PASSED with original sing-box pointer 3222c8c8. Windows
c-shared DLL (42,351,104 bytes) and Android arm64 CLI (44,695,905 bytes) built
successfully with observed exit 0 on that pointer; full gomobile is CI-only.
Now UNCOMMITTED: submodule moved to final merged sing-box 76e4f8d5 to preserve
newer main's 1.13.21 changes. The first `-mod=readonly` check correctly FAILED
because integration go.mod needs dependency updates. Minimal `-mod=mod`
refresh and full retest are running; this intermediate tree is not release
ready until validated. Expected exact additional files: go.mod/go.sum,
hiddify-sing-box, test fixture file, and this handoff. No integration commit
has been pushed or merged yet.

User authorized finishing, verifying and merging the core fixes for the signed
Doctor Mobile 2.2.3 release. Original AnyTLS implementation and fixes in this
branch are Claude's work; Codex is validating the integration and release path.

Material change, currently UNCOMMITTED: `v2/profile/test/profile_test.go` now
serves a fixed subscription from httptest and runs its database/profile writes
inside a temporary working directory. Before this change the full release-tag
suite failed in TestAddByContent because it downloaded the mutable upstream
`hiddify-next/main/test.configs/warp`, whose contents now include unsupported
Psiphon/URI content and a different title. The import, metadata and persistence
assertions are preserved. This test file was identical on base 784a8823.
Validation of the replacement fixture is running; no result claimed yet.

Verified original head a6356fea: recursive submodules initialized, sing-box
3222c8c8 and ray2sing e22a2eaf. Full release-tag `go test ./...` ran and FAILED
only in that mutable-fixture profile test (all other packages passed). Android
CI run 38937862876 passed its native build on that head. Local Windows c-shared
and Android arm64 native build checks are running, not yet claimed passed.

Sing-box vendored AnyTLS `go test -mod=readonly -race -count=3 ./...` PASSED
with observed exit 0 (session package 119.624s). Mihomo full `go test
-mod=readonly ./...` PASSED with persisted exit 0. Initial interrupted checks
without exit status were rerun; their log text alone was not counted as pass.
All four Sing-box Codex review threads are resolved; no review threads exist
on Mihomo PR4 or this PR1. No PR merged, core tag created or release published
by this Codex session at this checkpoint.

Remaining: validate fixture and final integrated dependency tree, final tests
and native builds, update the sing-box pointer if main integration changes it,
record exact commits/merge SHAs, and publish the required Mihomo core assets.
No phone/TUN live network behavior or original app signing is proven here.

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

Update, same day: the submodule pointer moved on twice.
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

- 263a68ec (second Codex finding): a SYNACK is timed only against its own
  stream's SYN. A late SYNACK for an earlier stream was timed against the
  next stream's SYN, a sample far too short. peerVersion is now atomic, an
  upstream data race the new test exposed. The submodule points at 263a68ec.

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
