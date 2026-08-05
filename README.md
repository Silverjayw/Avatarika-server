# AVATARIKA Game Restoration

## Overview

AVATARIKA is an abandoned online game (Steam AppID: 583740). This project contains research and tools to bring the game back online by understanding its file structure, startup flow, network stack, and API requirements.

## Current Status

- **Game launches and loads perfectly** after bypassing the launcher requirement
- After connecting to the server, the game **loses connection** during loading
- The game needs the full API implementation to complete loading
- Packet capture (`avatarika2.pcapng`) shows the actual API traffic during the loading process

## Quick Start

```bash
cd /home/sanitar/Desktop/AVATARIKA
chmod +x run_avatnika.sh
./run_avatnika.sh
```

Or manually:

```bash
cd /home/sanitar/Desktop/AVATARIKA
python3 client.exe /24B3D4DC-BA6D-4ECD-94D5-F7C2F9EDDE7B /gamexp_sid /pid /locale /distributor
```

## Launch Chain

```
Steam → Proton → Gamexp Launcher (launchpoint.exe) → client.exe
```

### Bypassing the Launcher

The launcher (`launchpoint.exe`) passes CLI arguments to `client.exe` from `gmxp-info.json`. Providing these arguments directly to `client.exe` bypasses the "run start exe first" error:

```
client.exe /24B3D4DC-BA6D-4ECD-94D5-F7C2F9EDDE7B /gamexp_sid /pid /locale /distributor
```

## Key Files

### Game Files (Steam)
- `launchpoint.exe` — Gamexp launcher (Go 386 binary)
- `client.exe` — Game client (MSVC PE32 binary)
- `connectn.cfg` — Server connection config (already points to 127.0.0.1)
- `game.ini` — Game config (realm=localhost, Port=25859)
- `url.ini` — URL config (127.0.0.1)
- `urld.ini` — Auth URL (www.avatarika.gamexp.ru/reg.php)
- `gmxp-cfg/init/connect.cfg` — Gamexp connection config
- `params/servers.cfg` — Server list
- `gmxp-info.json` — Gamexp API arguments
- `lnimclient.dll` — Launcher IPC module

### Research & Tools
- `protocol_analyzer.py` — Binary protocol analyzer
- `mock_auth_server.py` — Mock auth server (port 8443)
- `mock_game_server.py` — Mock game server (port 25858)
- `run_avatnika.sh` — Wrapper script to run client.exe with required args
- `avatarika.pcapng` — Original packet capture
- `avatarika2.pcapng` — Packet capture during loading (168k packets, 181MB)

## Network Architecture

### Binary Protocol Ports
- **27018** — TLS port (Steam internal)
- **38560** — Internal game port
- **57343** — Internal game port (main game communication)

### API Connections (from avatarika2.pcapng)
- **87.240.190.75:443** — Gamexp API (TLS, SNI=*.vk.com)
- **162.159.130.235:8443** — Gamexp auth (TLS, Cloudflare)
- **205.196.6.132:27018** — Steam network

### TLS Details
- **SNI**: `*.vk.com` (VKontakte CDN)
- **Protocol**: TLS 1.3
- **Cipher**: TLS_AES_256_GCM_SHA384
- **Certificate**: CN=www.vk, issued by VK CA
- **WebSocket**: `wss://accesspoint-api.gamexp.com:8443/app?v=...`

### Local Connections (during loading)
- **127.0.0.1:25858** — Game server
- **127.0.0.1:25859** — Game server (Port=25859 from game.ini)
- **127.0.0.1:57343** — Internal game port
- **127.0.0.1:38560** — Internal game port

## API Endpoints

### Auth Server (HTTPS:8443)
- `POST /lp/v2/api.php` — Authentication API
- `GET /health` — Health check
- `GET /authenticator` — Authenticator info

### Game Server (TCP:25858/25859)
- Binary protocol with 4-byte headers
- Types: 0x01=keepalive, 0x02=data, 0x05=extended, 0x0d/0x0e=ACK, 0x19=events

### Required Implementation
The game loses connection after initial handshake. The following API components need implementation:
1. **WebSocket Secure server** on port 8443 (wss://)
2. **Game server** on ports 25858-25868 and 57343
3. **Full API protocol** matching the binary format captured in the PCAP
4. **Authentication flow** (phone verification 5-step, password, system verify)

## Packet Analysis (avatarika2.pcapng)

### Capture Details
- **Duration**: 131 seconds
- **Packets**: 168,708
- **Size**: 181 MB
- **Rate**: 11 Mbps average

### Key Findings
1. Client connects to `87.240.190.75:443` with TLS SNI `*.vk.com`
2. TLS handshake uses TLS 1.3 with AES-256-GCM
3. Server responds with certificate chain from VK CA
4. After TLS handshake, client sends API requests
5. Server returns responses that the game processes during loading
6. Game eventually loses connection, indicating incomplete API implementation

### Protocol Flow
1. Client connects to 87.240.190.75:443 (TLS)
2. TLS handshake completes (SNI=*.vk.com)
3. Client sends API request
4. Server responds with data
5. Client connects to local game servers (25858, 57343, etc.)
6. Game loads and displays content
7. Game attempts to connect back to API
8. Connection lost (incomplete API implementation)

## Registry Keys

Created under `HKCU\Software\GameXP\Games`:
- `LaunchPoint=1`
- `Authenticated=1`
- `SessionValid=1`

## Hosts File

Modified `/etc/hosts` to redirect Gamexp domains to 127.0.0.1:
- `avatarika.gamexp.ru` → 127.0.0.1
- `accesspoint-api.gamexp.com` → 127.0.0.1
- All `*.gamexp.com` → 127.0.0.1

## Next Steps

1. **Implement WebSocket Secure server** on port 8443 matching the captured protocol
2. **Implement game server** on ports 25858-25868 and 57343
3. **Analyze binary protocol** from the PCAP to understand the exact message format
4. **Test with mock server** to verify the game completes loading
5. **Explore client.exe modification** to skip launcher requirements entirely

## References

- [Steam App Page](https://store.steampowered.com/app/583740/)
- [Gamexp API Documentation](https://accesspoint-api.gamexp.com)
- [VK CA Certificates](https://www.vk.com)
# Avatarika-server
# Avatarika-server
