# AVATARIKA Game Restoration

## Overview

AVATARIKA is an abandoned online game (Steam AppID: 583740). This project contains research and tools to bring the game back online by understanding its file structure, startup flow, and network stack.

## Current Status

- **Game launches and loads the full UI** (login screen, avatar, game world) when connected to the accesspoint
- **Connection is lost after ~131 seconds** during game loading — the accesspoint sends something the client can't parse
- The game connects to **local servers** (127.0.0.1), not to the Internet
- `launchpoint.exe` is the **accesspoint server**, not just a launcher

## Quick Start

```bash
cd /home/sanitar/Desktop/AVATARIKA
chmod +x run_avatnika.sh
./run_avatnika.sh
```

Or manually:

```bash
cd /home/sanitar/Desktop/AVATARIKA
python3 mock_accesspoint_tls.py
python3 mock_game_server.py
python3 mock_auth_server.py
chmod +x run_avatnika.sh
./run_avatnika.sh
```

## Launch Chain

```
Steam → Proton → launchpoint.exe (accesspoint server) → client.exe
```

### Bypassing the Launcher

`launchpoint.exe` can be started directly with CLI arguments from `gmxp-info.json`:

```bash
./launchpoint.exe /24B3D4DC-BA6D-4ECD-94D5-F7C2F9EDDE7B /gamexp_sid /pid /locale /distributor
```

### Connecting Client.exe Directly

```bash
./client.exe /24B3D4DC-BA6D-4ECD-94D5-F7C2F9EDDE7B /gamexp_sid /pid /locale /distributor
```

The client connects directly to the accesspoint on 127.0.0.1:27018 (TLS) and local game servers on 127.0.0.1:25858, 127.0.0.1:38560, 127.0.0.1:57343.

## Key Files

### Game Files (Steam)
- `launchpoint.exe` — Accesspoint server (Go 386 binary, PE32, 7 sections, stripped to external PDB)
- `client.exe` — Game client (MSVC PE32, 32-bit binary)
- `connectn.cfg` — Server connection config (already points to 127.0.0.1)
- `game.ini` — Game config (realm=localhost, Port=25859)
- `url.ini` — URL config (127.0.0.1)
- `urld.ini` — Auth URL (www.avatarika.gamexp.ru/reg.php)
- `gmxp-info.json` — Gamexp API arguments
- `lnimclient.dll` — Launcher IPC module

### Research & Tools
- `mock_accesspoint_tls.py` — TLS accesspoint server (port 27018, custom 0x17 records)
- `mock_game_server.py` — Game server (port 25858, binary protocol)
- `mock_auth_server.py` — Auth server with CA-signed cert (port 8443)
- `pcap_deep_analyzer.py` — Manual TLS record parser for custom 0x17 records
- `protocol_analyzer.py` — Binary protocol analyzer
- `run_avatnika.sh` — Wrapper script to run client.exe with required args
- `avatarika.pcapng` — Original packet capture
- `avatarika2.pcapng` — Packet capture during loading (168k packets, 181MB, 131 seconds)

## Network Architecture

### Accesspoint Server (launchpoint.exe)
- **127.0.0.1:27018** — TLS server (SNI=`*.gamexp.com`, TLS 1.3, custom record type 0x17)
- **127.0.0.1:25858** — Local game server (plain TCP, binary protocol)

### Client Connections
| Port | Protocol | Purpose |
|------|----------|---------|
| 27018 | TLS 1.3 (custom 0x17 records) | Accesspoint communication |
| 25858 | Plain TCP | Game server |
| 38560 | Plain TCP | Internal game communication |
| 57343 | Plain TCP | Internal game communication |

### Binary Protocol Structure
All TCP connections use a 4-byte header:
```
[0]   type     (1 byte)
[1-3] length   (3 bytes, big-endian)
[4]   sub_type (1 byte)
[5-6] length   (2 bytes, big-endian)
[7+]  payload  (variable length)
```

**Known types:**
- `0x01` — Keepalive
- `0x02` — Data (messages)
- `0x05` — Extended
- `0x0d` / `0x0e` — ACK
- `0x19` — Events

**Custom 0x17 records (TLS):**
- Header: `[type:1][length:3][sub_type:1][length:2]`
- Payload: TLS-encrypted (not raw binary)

### TLS Details
- **SNI**: `*.gamexp.com` (accesspoint), `*.vk.com` (CDN)
- **Protocol**: TLS 1.3
- **Cipher**: TLS_AES_256_GCM_SHA384
- **Certificate**: CN=www.vk, issued by VK CA

## Authentication

`launchpoint.exe` connects to the Gamexp API at `accesspoint-api.gamexp.com:8443` and implements the following auth flow:

1. **Phone verification (5-step EAP)**: Send code → validate → confirm → retry → confirm
2. **Password authentication**: Send phone+password → receive token
3. **System verification**: Send token → verify → complete

The `launchpoint.exe` binary uses **WebSocket Secure** (`Sec-WebSocket-Version` header) to connect to the API.

## Game Behavior

1. Client starts and connects to accesspoint (127.0.0.1:27018)
2. Client connects to game servers (127.0.0.1:25858, 38560, 57343)
3. Game loads and displays the **full UI** (login screen, avatar, game world)
4. Game processes data from accesspoint and game servers
5. **Connection is lost after ~131 seconds** — the accesspoint sends something the client can't parse

## What's Working

- ✅ Client launches without errors
- ✅ Client connects to accesspoint on 127.0.0.1:27018 (TLS)
- ✅ Client connects to game servers on 127.0.0.1:25858, 38560, 57343
- ✅ Game displays the full UI (login screen, avatar, game world)
- ✅ TLS handshake completes successfully

## What's Not Working

- ❌ **Custom 0x17 record payload structure unknown** — can't parse the encrypted payload
- ❌ **Binary protocol sub_types for 0x02/data** — only confirmed `0x00` (ACK) and `0x01` (events)
- ❌ **Initial handshake sequence** — does the client send something before connecting to 27018?
- ❌ **38560 and 57343 protocols** — not enough captured traffic to understand these

## Next Steps

1. **Capture more traffic** — get a full TLS handshake on 27018 to see the initial client message
2. **Decipher 0x17 record payload** — need the actual accesspoint traffic to understand the encrypted format
3. **Map binary protocol sub_types** — identify all message types for 0x02/data
4. **Implement full accesspoint** — handle the complete binary protocol
5. **Test with real accesspoint** — once the protocol is understood, test against the real server

## References

- [Steam App Page](https://store.steampowered.com/app/583740/)
- [Gamexp API Documentation](https://accesspoint-api.gamexp.com)
- [VK CA Certificates](https://www.vk.com)
