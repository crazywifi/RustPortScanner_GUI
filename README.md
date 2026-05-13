# PortScanner v2.1

**nmap-style port scanner with an embedded production-quality web GUI**

Replaces the FLTK native GUI (v1.0) with an embedded HTTP server that serves a responsive, professional browser-based interface. All scanning logic is preserved — only the UI layer changed.

---

## What Changed (v1.0 → v2.1)

| Issue in v1.0 | Resolution in v2.1 |
|---|---|
| Fixed 1240×800 window, not resizable | Fully responsive browser UI — resize freely |
| No maximize / fullscreen | Browser fullscreen (F11) works natively |
| FLTK dependency (complex native build) | `tiny_http` only — minimal dependency |
| Open/closed/filtered mixed in one flat list | Open ports shown prominently; closed/filtered collapsed with counts, expandable on demand |
| Poor data readability | Per-host cards with port tables, state badges (green/red/yellow), service names |
| No live streaming | Results stream in real-time via chunked HTTP / NDJSON |
| No scan rate display | Live ports/sec counter in topbar |
| No activity log | Timestamped activity log panel with color-coded entries |
| No search / sort | Filter by state, free-text search, sort by port/host/service/state |
| No Pause button | Pause (saves state) + Stop buttons during scan |
| Export limited | CSV / JSON / TXT export from browser |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  portscanner binary                                  │
│                                                      │
│  ┌──────────────┐    HTTP     ┌───────────────────┐  │
│  │  tiny_http   │◄───────────│  Browser (any)    │  │
│  │  web server  │            │  localhost:7681    │  │
│  │  :7681       │────────────►  index.html (emb) │  │
│  └──────┬───────┘   NDJSON   └───────────────────┘  │
│         │ stream                                      │
│  ┌──────▼───────┐                                    │
│  │  Scan engine │  TCP Connect / SYN Stealth / UDP   │
│  │  thread pool │  (identical to v1.0)               │
│  └──────────────┘                                    │
└─────────────────────────────────────────────────────┘
```

The HTML UI (`src/index.html`) is embedded into the binary at compile time via `include_str!`. No external files are needed at runtime.

---

## Requirements

| Platform | Requirement |
|---|---|
| Linux    | `libpcap-dev` (for SYN/UDP modes; TCP Connect needs nothing) |
| macOS    | Xcode Command Line Tools (libpcap included) |
| Windows  | [Npcap](https://npcap.com) + SDK (for SYN mode); TCP Connect works without it |

All platforms require **Rust stable** (1.70+): https://rustup.rs

---

## Build

**Linux:**
```bash
chmod +x build_linux.sh && ./build_linux.sh
```

**macOS:**
```bash
chmod +x build_macos.sh && ./build_macos.sh
```

**Windows:**
```batch
build_windows.bat
```

**Manual:**
```bash
cargo build --release
# Binary: ./target/release/portscanner  (or .exe on Windows)
```

---

## Usage

### Web GUI (recommended)
```bash
./portscanner --gui
# Opens http://127.0.0.1:7681 in your default browser automatically
```

### CLI mode
```bash
# Single host
./portscanner 192.168.1.1 -p 1-1024

# CIDR range, top 100 ports, fast
./portscanner 10.0.0.0/24 -F -t 500 -T 200

# SYN stealth scan (requires root)
sudo ./portscanner 192.168.1.1 --syn -p 1-65535

# Save results
./portscanner 192.168.1.1 -p top100 -o results
# → results.txt, results.json

# From file list
./portscanner -iL targets.txt -p 80,443,8080

# Pause (Ctrl+C saves state), then resume
./portscanner 10.0.0.0/24 -p 1-65535
# [Ctrl+C → writes scan_state.json]
./portscanner --resume scan_state.json
```

### All CLI flags
```
-p <spec>       Port spec: 22,80,443 | 1-1024 | top100 | 1-65535
-F              Fast mode (nmap top-100 ports)
-t <n>          Thread count (default: 100)
-T <ms>         Timeout per port in ms (default: 500)
-o <base>       Save to <base>.txt + <base>.json
-iL <file>      Load targets from file
--syn           SYN Stealth scan (needs root)
--udp           UDP scan (needs root)
--state <file>  State file name (default: scan_state.json)
--resume <file> Resume from saved state
--gui           Launch web GUI
--help          Show help
```

---

## Web GUI Features

- **Live streaming** — ports appear as they are scanned
- **Per-host cards** — each target gets its own card with open ports table
- **State segregation** — open ports are immediately visible; closed/filtered shown as counts with optional expand
- **State badges** — green OPEN, red CLOSED, yellow FILTERED
- **Stats panel** — hosts scanned, open/closed/filtered counts update live
- **Progress bar** — port count, percentage, elapsed time, ETA
- **Scan rate** — live ports/second counter
- **Activity log** — timestamped entries, color-coded by severity
- **Search & filter** — filter by state, free-text search (port/service/host), sort options
- **Export** — download results as CSV, JSON, or nmap-style TXT
- **Raw output** — nmap-style text report with "Not shown: N closed" summaries
- **CLI preview** — generated command updates live as you change settings
- **Copy CLI** — one-click copy of the CLI command
- **Pause / Resume** — mid-scan pause saves state to disk; resume via UI or CLI
- **Reset** — clear all fields and results with one click

---

## Port presets

| Preset | Ports |
|---|---|
| Common | 21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5900,8080 |
| Top100 | nmap's top 100 most common ports |
| Full   | 1–65535 |
| Web+DB | 80,443,8080,8443,3306,5432,1433,1521,6379,27017 |
| Dev    | 3000,4000,5000,8000,8080,8888,9000,3001,4200,5173 |
| SMB    | 135,137,138,139,445,593 |

---

## Differences from nmap

- TCP Connect mode performs full 3-way handshake (same as `nmap -sT`)
- SYN mode sends raw SYN packets and listens for SYN-ACK (same as `nmap -sS`)
- Service detection is name-only (no version probing)
- No OS detection, no scripting engine
- CIDR expansion is done in-process (no DNS for PTR records)

---

## License

MIT
