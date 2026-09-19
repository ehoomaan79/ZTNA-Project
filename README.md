# Zero Trust Network Access (ZTNA) Project

A secure client/server communication system implementing Zero Trust Network Access principles. This project demonstrates direct peer-to-peer encrypted communication after server-mediated authentication and authorization.

## Architecture

```
Client A                    Server                    Client B
  |                          |                          |
  |----------- TLS --------->|                          |
  |<---------- TLS ----------|                          |
  |                          |                          |
  | (Authentication &        |                          |
  |  Authorization)          |                          |
  |                          |                          |
  |<------ Encrypted UDP --->| (Direct P2P, no relay)  |
```

## Features

- **Zero Trust Authentication**: Mutual TLS + password-based authentication with PBKDF2
- **Session Management**: Time-limited tokens with secure validation
- **Access Control**: Configurable peer-to-peer access policies
- **NAT Traversal**: UDP hole punching for direct peer connectivity
- **End-to-End Encryption**: X25519 key exchange + AES-256-GCM
- **Protocol**: JSON-based messaging over TLS/TCP (control) and UDP (data)

## Versions

| Version | Description | Tag |
|---------|-------------|-----|
| 0.7 | Hard-coded single message transfer | `v0.7` |
| 0.8 | Interactive chat with readline support | `v0.8` |

## Requirements

- Python 3.8+
- `cryptography` library

```bash
pip install cryptography
```

## Quick Start

### Server

```bash
# Version 0.7
cd version_0.7
python3 -m server.main

# Version 0.8
cd version_0.8
python3 -m server.main
```

Server listens on:
- TLS/TCP: `0.0.0.0:8443`
- UDP: `0.0.0.0:8444`

Self-signed certificates are auto-generated on first run.

### Client

```bash
# Version 0.7 - Hard-coded message
cd version_0.7
python3 -m client.main --username client1 --password password123 --peer client2

# Version 0.8 - Interactive chat
cd version_0.8
python3 -m client.main --username client1 --password password123 --peer client2
```

#### Client Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--server` | `127.0.0.1` | Server hostname/IP |
| `--port` | `8443` | Server TLS port |
| `--udp-port` | `8444` | Server UDP port |
| `--cafile` | `certs/server.crt` | CA certificate for TLS verification |
| `--username` | *required* | Client username |
| `--password` | *required* | Client password |
| `--peer` | *optional* | Peer username to connect to |

If `--peer` is not specified, the client waits for incoming connections.

## Protocol Flow

1. **Client → Server**: TLS connection + `AUTH` (username/password)
2. **Server → Client**: `AUTH_RESPONSE` + `TOKEN` (time-limited)
3. **Client → Server**: `KEY_EXCHANGE` (X25519 public key)
4. **Client A → Server**: `PEER_REQUEST` (token + peer_id)
5. **Server → Both Clients**: `ENDPOINT_INFO` (IP, port, public key)
6. **Clients ↔ Clients**: UDP NAT traversal probes
7. **Direct P2P**: Encrypted UDP with AES-256-GCM (server no longer involved)

## Project Structure

```
version_0.7/ / version_0.8/
├── client/
│   ├── main.py          # Client entry point
│   └── connection.py    # TLS/UDP connection handling
├── common/
│   ├── protocol.py      # Message serialization/parsing
│   ├── security.py      # Crypto operations (X25519, AES-GCM, HKDF)
│   └── network.py       # NAT traversal, endpoint registration
├── server/
│   ├── main.py          # Server entry point + client handling
│   ├── authorization.py # Auth, tokens, access control
│   └── session.py       # Session management
├── certs/               # Auto-generated TLS certificates (gitignored)
├── docs/
│   ├── AI.txt           # Project documentation
│   └── Dependencies.txt # Requirements
└── misc/                # Large binaries (gitignored)
```

## Security Considerations

- **No server-side data relay**: Server only handles control plane
- **Forward secrecy**: Ephemeral X25519 keys per session
- **Authenticated encryption**: AES-256-GCM with unique nonces
- **Replay protection**: Nonce-based + timestamp validation
- **Self-signed TLS**: For control channel; verify fingerprint in production

## Development

### Running Tests

```bash
# Terminal 1: Start server
python3 -m server.main

# Terminal 2: Start client A
python3 -m client.main --username client1 --password password123 --peer client2

# Terminal 3: Start client B
python3 -m client.main --username client2 --password password456
```

### Protocol Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `AUTH` | C→S | Username/password authentication |
| `AUTH_RESPONSE` | S→C | Authentication result |
| `TOKEN` | S→C | Session token |
| `KEY_EXCHANGE` | C→S | X25519 public key |
| `PEER_REQUEST` | C→S | Request peer connection |
| `ENDPOINT_INFO` | S→C | Peer endpoint + public key |
| `NAT_PROBE` | C↔C/S | UDP hole punching |
| `DATA` | C↔C | Encrypted application data |
| `CLOSE` | Any | Connection termination |

## License

MIT License - See LICENSE file for details.

## References

- [Zero Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [X25519 Key Agreement](https://tools.ietf.org/html/rfc7748)
- [AES-GCM](https://tools.ietf.org/html/rfc5116)
- [HKDF](https://tools.ietf.org/html/rfc5869)