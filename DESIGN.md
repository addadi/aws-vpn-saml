# aws-vpn-saml Design Document

## Problem

The current `aws-vpn-client` binary (`/usr/bin/aws-vpn-client`, ethan605 Go build) is a fragile PoC that:
- Breaks on new OpenVPN versions (CRV1 message split across lines in 2.6.20)
- Blocks forever reading OpenVPN stdout (no timeout/early-exit on challenge found)
- No proper error handling (silent failures)
- No reconnection support (one-shot only)
- No config file support (flags only)
- Not maintained (last updated 2022)

## Existing Implementations Analyzed

### 1. samm-git/aws-vpn-client (Go, 2020) — The original PoC
- Simple `server.go` (HTTP listener on 35001) + `aws-connect.sh` (bash wrapper)
- Shell script runs OpenVPN with `ACS::35001`, grep's stdout for CRV1 URL, opens browser
- SAML server writes response to file, shell script reads it back
- **Problems**: Shell-based, no error handling, blocking, fragile grep parsing

### 2. ethan605/aws-vpn-client (Go) — Our current binary
- Wraps samm-git's approach into a single Go binary
- Supports `-on-challenge listen` (SAML server) and `-on-challenge auto` (follow URL with cookie)
- **Problems**: Blocking stdout reader, `AUTH_FAILED,CRV1:R` search breaks on OpenVPN version changes, no timeouts

### 3. jonathanxd/openaws-vpn-client (Rust/GTK) — AUR package `openaws-vpn-client-bin`
- Full GTK GUI, Rust rewrite of the SAML flow
- Bundles its own patched OpenVPN binary
- **Problems**: Messy code (author admits it), GTK dependency, crashes on unwrap(), tightly coupled GUI+SAML

### 4. donotnoot/samlvpn (Go) — Best designed existing solution
- Config-driven YAML, supports multiple VPN providers
- Clean separation: config → challenge → SAML callback → connect
- Can output OpenVPN command line or run it directly
- Includes its own OpenVPN patch for 2.5.x
- **Problems**: Go, only 28 commits, unmaintained, OpenVPN 2.5 era patches

### 5. openlawsvpn/openlawsvpn (Spec + impl) — Best specification
- Proper state machine: IDLE → PHASE_1 → WAITING_FOR_CHALLENGE → SAML_PENDING → TOKEN_CAPTURED → PHASE_2 → CONNECTED
- D-Bus mode (unprivileged, using openvpn3-linux services)
- Direct mode (root, using patched openvpn binary)
- Auto re-authentication on session expiry
- **Problems**: Python-based, references openvpn3 D-Bus which we don't use

### 6. jkroepke/openvpn-auth-oauth2 (Go) — Server-side OAuth2 for OpenVPN
- 471 stars, actively maintained
- Uses OpenVPN management interface properly
- **Not applicable** — this is server-side, but good architecture reference for management interface usage

### 7. OpenVPN 3 webauth spec — Official protocol
- Documents CRV1 format: `CRV1:<flags>:<state_id>:<username_base64>:<challenge_text>`
- Documents `AUTH_PENDING,cr-response` protocol
- `IV_SSO` client capability signaling
- **Key insight**: AWS doesn't use standard OpenVPN SSO — it uses a proprietary `ACS::port` hack

## Design Decisions

### Language: Rust

- Single static binary, no runtime dependencies
- Proper error handling with `Result<T, E>` (no silent failures)
- No GC pauses (relevant during SAML assertion handling)
- tokio async runtime for non-blocking I/O
- Already in our dependency tree (openaws-vpn-client-bin is Rust)
- Cross-compilation friendly (arm64 support)

### Architecture: CLI tool with clean separation

The binary has ONE job: produce 2 lines of output (username + password) that the `awsvpn` script feeds to OpenVPN. It does NOT manage the VPN connection itself.

```
┌─────────────────┐     stdout      ┌──────────────┐
│  aws-vpn-saml   │ ──────────────> │  awsvpn      │
│  (this binary)  │   N/A           │  (script)    │
│                 │   CRV1::sid::   │              │
│  Phase 1: ACS   │   <saml_resp>   │  runs sudo   │
│  Phase 2: SAML  │                 │  openvpn-aws │
└─────────────────┘                 └──────────────┘
```

This keeps the existing `awsvpn` script, systemd service, NM plugin, multi-VPN routing ALL untouched.

### State Machine (inspired by openlawsvpn)

```
IDLE
  ↓
PHASE1_CONNECT  ──  Run openvpn-aws with ACS::35001
  ↓
CHALLENGE_WAIT  ──  Parse stdout for CRV1 URL (async, with timeout)
  ↓
SAML_PENDING    ──  Start HTTP server on :35001, open browser
  ↓                  (OR use -on-challenge auto for headless)
TOKEN_CAPTURED  ──  Receive SAMLResponse via POST
  ↓
DONE            ──  Output credentials to stdout, exit 0
```

Error states:
- `CHALLENGE_TIMEOUT` — OpenVPN didn't produce CRV1 in 30s
- `SAML_TIMEOUT` — User didn't complete browser login in 120s
- `INVALID_CHALLENGE` — CRV1 format unexpected

### Key Features (improvements over all existing implementations)

1. **Version-agnostic CRV1 parsing** — Search for `CRV1:R` fragments, handle split lines across OpenVPN versions (2.4.x, 2.5.x, 2.6.x, 2.7.x)
2. **Non-blocking** — All I/O is async (tokio), no blocking reads
3. **Proper timeouts** — Configurable on every phase
4. **Two challenge modes**:
   - `listen` (default): Start SAML HTTP server on configurable port, open browser
   - `auto`: Follow challenge URL programmatically (for headless/CICD)
5. **Config file support** — YAML/TOML at `~/.config/awsvpn/saml.yaml`
6. **Structured logging** — JSON lines to stderr (compatible with our awsvpn-logger)
7. **Credential security** — Never write SAML assertion to disk, pipe via stdin
8. **Exit codes** — 0=success, 1=config error, 2=challenge failed, 3=SAML timeout, 4=auth failed

### CLI Interface (backward-compatible with ethan605)

```
aws-vpn-saml -ovpn /usr/bin/openvpn-aws -config ~/.config/awsvpn/endpoints/default.ovpn [-on-challenge listen|auto] [-verbose] [-port 35001] [-timeout 120]
```

Also supports environment variables (like ethan605):
```
AWS_VPN_OVPN_BIN, AWS_VPN_OVPN_CONF, AWS_VPN_ON_CHALLENGE, AWS_VPN_VERBOSE
```

### Config File (~/.config/awsvpn/saml.yaml)

```yaml
ovpn_bin: /usr/bin/openvpn-aws
ovpn_conf: ~/.config/awsvpn/endpoints/default.ovpn
on_challenge: listen          # listen | auto
saml_port: 35001
challenge_timeout: 30         # seconds to wait for CRV1
saml_timeout: 120             # seconds to wait for browser login
verbose: false
log_format: json              # json | text
```

### SAML Server

HTTP server on configurable port (default 35001):
- `POST /` — Receives `SAMLResponse` form field, returns success page
- `GET /health` — Health check endpoint
- Proper CORS headers for browser compatibility
- Auto-shutdown after receiving response

### Error Handling

Every error produces a structured JSON log line to stderr:
```json
{"ts":"2026-05-09T12:00:00Z","level":"error","phase":"challenge_wait","msg":"CRV1 not found","duration":30}
```

### Testing Strategy

- Unit tests for CRV1 parsing (various OpenVPN output formats)
- Unit tests for SAML server
- Integration test: run against real VPN endpoint (manual)

### Build & Distribution

- Cargo build → single static binary
- GitHub Actions CI (linux/amd64 + linux/arm64)
- Released via aws-vpn-saml GitHub repo (already set up with GoReleaser, will switch to Rust)
- `make install` copies to /usr/bin/aws-vpn-saml

## Implementation Plan

1. **Phase 1**: Core SAML helper in Rust (replace ethan605 binary)
   - CRV1 challenge parser (version-agnostic)
   - SAML HTTP server
   - CLI interface (backward-compatible flags)
   - Structured logging
   - Config file support

2. **Phase 2**: Robustness
   - Connection health check
   - Auto-retry with stale session detection
   - Graceful shutdown on SIGTERM/SIGINT

3. **Phase 3**: Advanced features
   - Headless mode (auto challenge without browser)
   - SAML assertion caching
   - Multiple endpoint support
