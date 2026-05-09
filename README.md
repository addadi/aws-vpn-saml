# aws-vpn-saml

SAML authentication helper for AWS Client VPN on Linux.

Opens the system browser for AWS SSO/SAML authentication, captures the
SAML assertion via localhost redirect, and outputs credentials for the patched
OpenVPN binary ([openvpn-aws](https://github.com/addadi/openvpn-aws)).

Implements the full CRV1 challenge-response flow: connects to the VPN endpoint,
extracts the CRV1 challenge, opens a browser for SAML auth, captures the response
on a local HTTP server, and outputs OpenVPN-compatible credentials.

Written in Rust. ~1.7MB static binary (vs 10.7MB Go). Auth completes in ~3 seconds.

## Attribution

Based on [aws-vpn-client](https://github.com/ethan605/aws-vpn-client) by ethan605.
Not a direct fork, but uses the same SAML capture approach and protocol.

## Install

Download from [GitHub Releases](https://github.com/addadi/aws-vpn-saml/releases):

```bash
curl -sL https://github.com/addadi/aws-vpn-saml/releases/latest/download/aws-vpn-saml-linux-amd64 -o aws-vpn-saml
chmod +x aws-vpn-saml
```

## Build

Requires Rust 1.70+:

```bash
cargo build --release
# Binary at target/release/aws-vpn-saml
```

## Usage

This is a helper — not meant to be run directly. It's invoked by the
AWS VPN connection scripts during the SAML authentication phase.

```bash
aws-vpn-saml --endpoint cvpn-endpoint-XXXXX.prod.clientvpn.amazonaws.com
```

## Design

See [DESIGN.md](DESIGN.md) for the full architecture, state machine, and
CRV1 protocol documentation.

## License

MIT
