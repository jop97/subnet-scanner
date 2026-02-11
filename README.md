# Subnet Scanner v1.1.0

A real-time network scanning web application built with Flask, Socket.IO, and Nmap. Discover hosts on your network with a clean dark UI featuring a visual IP grid, live status updates, and detailed host information.

![Version](https://img.shields.io/badge/Version-1.1.0-cyan)
![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Table of Contents

- [Features](#features)
- [Platform Support](#platform-support)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Settings Modal](#settings-modal)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [API Reference](#api-reference)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

---

## Features

### Scan Modes

| Button | What it does |
|--------|-------------|
| **Quick Sweep** | Fast ICMP ping sweep only. Discovers which hosts are online/offline with response time, hostname, and TTL-based OS guess. |
| **Full Scan** | Ping sweep **+** Nmap port/service scan **+** deep scan probes on every online host. Runs automatically in sequence: ping > nmap > HTTP/SSL/banner/SSDP/ARP/MAC vendor. All probes are individually toggleable in Settings. |

### Deep Scan Probes (Full Scan)
- **Nmap port & service detection**  Top 20 ports with version fingerprinting (`-sV`)
- **HTTP/HTTPS probing**  Server header, page title, redirect chain, security headers (separate sections for HTTP and HTTPS)
- **SSL/TLS certificate analysis**  Subject, issuer, validity dates, SANs, cipher suite, port indicator
- **TCP banner grabbing**  Raw banners from SSH, FTP, SMTP, MySQL, RDP, and more (with protocol names)
- **MAC vendor lookup**  OUI database resolves MAC addresses to manufacturer names (e.g. `Intel Corporate`, `Apple, Inc.`)
- **SSDP/UPnP discovery**  Multicast M-SEARCH finds smart devices, routers, IoT, media servers
- **Full ARP table scan**  Reads all known MACs on the network in one call before per-host scanning
- **TTL-based OS guessing**  Immediate OS family guess (Linux/Windows/Network Device) from ping TTL
- **WHOIS lookup**  Basic WHOIS information for the IP address

### Host Detail Modal
Click any host for a deep-dive view combining all scan data:
- **Basic info** — IP, status, hostname, response time, reverse DNS, MAC address, vendor (OUI), NetBIOS name & workgroup
- **All hostnames** — Full nmap hostnames array with type labels (PTR, user, etc.)
- **Port & service table** — With version info, CPE identifiers per service, and per-port NSE script output
- **OS fingerprinting** — Nmap matches with OS classes (type, vendor, family, generation) and CPE, or TTL guess
- **DNS / reverse DNS / PTR records**
- **HTTP response info** — Status code, server, title, redirect, security headers (separate HTTP and HTTPS sections with port indicators)
- **SSL/TLS certificate details** — Protocol, cipher, subject, issuer, validity, SANs, port indicator
- **TCP service banners** — With protocol names for known ports
- **UPnP/SSDP device info** — Server, services, location URI
- **NSE host scripts** — Host-level nmap script output
- **System info** — Uptime (human-readable + seconds), last boot, TCP sequence prediction (class, difficulty, index, values)
- **WHOIS information** — Raw WHOIS data in scrollable panel
- **Error & status notices** — Inline alerts for scan errors or limited data

### Views & Filtering
- **Grid View**  Compact color-coded IP grid, sorted by IP. Click any block for full details.
- **List View**  Full-width sortable, searchable table with columns: status, IP, hostname, response time, open ports, OS, MAC/vendor, and action buttons.
- **Filters**  Toggle between All / Online / Offline hosts in both views.

### Live Monitoring
- **Live Update**  Toggle to re-ping all discovered hosts on a schedule. Intervals: 30s, 1min, 2min, 5min, 10min.
- **Status Card**  Real-time state indicator (Idle / Scanning / Live / Done / Error) with progress bar.

### Customization
- **Settings Modal**  Scan parameters, deep scan probe toggles, display preferences, notifications, live update behavior. All persisted in localStorage.
- **Keyboard Shortcuts**  `Ctrl+Enter` to start scan, `Escape` to stop.
- **Fullscreen Mode**  Toggle from the navbar.

---

## Platform Support

| Feature                     | Windows | Linux | macOS |
|-----------------------------|:-------:|:-----:|:-----:|
| Ping sweep                  | Yes     | Yes   | Yes   |
| Nmap port/service scanning  | Yes     | Yes   | Yes   |
| OS fingerprinting (-O)      | Admin   | sudo  | sudo  |
| DNS / reverse DNS           | Yes     | Yes   | Yes   |
| MAC address (ARP table)     | Yes     | Yes   | Yes   |
| MAC vendor lookup (OUI)     | Yes     | Yes   | Yes   |
| SSDP/UPnP discovery         | Yes     | Yes   | Yes   |
| HTTP/SSL/banner probing     | Yes     | Yes   | Yes   |
| NetBIOS name resolution     | Yes*    | Yes** | No    |
| `start.bat` auto-setup    | Yes     | No    | No    |
| Live Update                 | Yes     | Yes   | Yes   |

\* Windows uses `nbtstat -A`. \*\* Linux requires `samba-common` (`sudo apt install samba-common`).

### No Admin Required

The scanner runs **without administrator privileges** on all platforms. On Windows, `--unprivileged` is automatically passed to Nmap to prevent UAC popups. This uses TCP connect scans instead of SYN scans  slightly slower but fully functional without elevation.

Running as admin/sudo enables additional Nmap features: OS detection (`-O`), SYN scan (`-sS`), and more accurate service fingerprinting.

---

## Tech Stack

| Layer    | Technology                                                  |
|----------|-------------------------------------------------------------|
| Backend  | Flask 3.1, Flask-SocketIO 5.4, threading async mode         |
| Scanner  | python-nmap 0.7.1, subprocess (ping), dnspython 2.7        |
| Probes   | requests (HTTP), ssl (certs), socket (banners), mac-vendor-lookup |
| Frontend | Bootstrap 4.6, Socket.IO 4.7, DataTables 1.13, Font Awesome 6.5 |
| Styling  | Custom dark theme with CSS variables and Inter web font     |
| Runtime  | Python 3.10+ (tested up to 3.14), Nmap 7.x                 |

### Python Dependencies

| Package              | Version  | Purpose                                    |
|----------------------|----------|--------------------------------------------|
| `flask`            | 3.1.0    | Web framework                              |
| `flask-socketio`   | 5.4.1    | WebSocket support for real-time updates    |
| `eventlet`         | 0.37.0   | Async networking (listed for compat, not used) |
| `python-nmap`      | 0.7.1    | Python wrapper for Nmap                    |
| `dnspython`        | 2.7.0    | DNS record lookups (PTR, reverse DNS)      |
| `requests`         | >=2.31.0 | HTTP/HTTPS probing                         |
| `mac-vendor-lookup`| >=0.1.12 | MAC address to vendor name (OUI database)  |

> **Note on async mode:** The app uses `async_mode="threading"` instead of eventlet due to compatibility issues with Python 3.13+.

---

## Quick Start

### Prerequisites

- **Python 3.10+**  [python.org/downloads](https://www.python.org/downloads/)
- **Nmap**  [nmap.org/download](https://nmap.org/download.html) (must be in PATH)

#### Installing Nmap

**Windows:** Download the installer from [nmap.org](https://nmap.org/download.html). Check **"Add Nmap to PATH"** during installation. Npcap will be installed alongside it.

**Ubuntu / Debian:**
```bash
sudo apt update && sudo apt install nmap
```

**Fedora / RHEL:**
```bash
sudo dnf install nmap
```

**macOS (Homebrew):**
```bash
brew install nmap
```

**Arch Linux:**
```bash
sudo pacman -S nmap
```

### Windows (recommended)

Clone the repository and double-click `start.bat`:

```
git clone https://github.com/jop97/subnet-scanner.git
cd subnet-scanner
start.bat
```

The batch script will automatically:
1. Verify Python and Nmap are installed and in PATH
2. Create a `.venv` virtual environment (first run only)
3. Install all dependencies from `requirements.txt`
4. Open your default browser at `http://localhost:5000`
5. Start the Flask development server

**No administrator privileges required.** The scanner works fully without elevation.

### Linux / macOS

```bash
git clone https://github.com/jop97/subnet-scanner.git
cd subnet-scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000** in your browser.

### Running with Elevated Privileges (optional)

Elevated privileges enable additional Nmap features but are **not required**:

**Windows:** Right-click `start.bat` > Run as administrator.

**Linux / macOS:**
```bash
sudo .venv/bin/python app.py
```

This enables: OS detection (`-O`), SYN scan (`-sS`), MAC address via Nmap on local network, more accurate service fingerprinting. Without elevation, the app still works with TCP connect scans.

---

## Configuration

### config.py / Environment Variables

| Setting             | Default                          | Description                            |
|---------------------|----------------------------------|----------------------------------------|
| `SECRET_KEY`      | `subnet-scanner-secret-...`    | Flask secret key for session security  |
| `MAX_THREADS`     | `100`                          | Maximum parallel ping threads          |
| `PING_TIMEOUT`    | `1`                            | Ping timeout in seconds                |
| `NMAP_TIMEOUT`    | `30`                           | Nmap scan timeout in seconds           |
| `DEFAULT_NMAP_ARGS` | `-sV -sC -O --top-ports 100` | Default Nmap arguments for detail scans |

**Windows (PowerShell):**
```powershell
$env:MAX_THREADS = 200
python app.py
```

**Linux / macOS:**
```bash
MAX_THREADS=200 python app.py
```

---

## Settings Modal

The Settings modal (gear icon in the navbar) provides runtime configuration. All settings are **persisted in localStorage** and applied immediately. Click **Reset** to restore defaults.

### Quick Sweep
| Setting            | Default | Description                                    |
|--------------------|---------|------------------------------------------------|
| Ping Timeout (ms)  | 1000    | Maximum wait time per host ping                |
| Concurrent Threads | 50      | Number of parallel scan threads                |

### Full Scan
| Setting              | Default                   | Description                                    |
|----------------------|---------------------------|------------------------------------------------|
| Nmap Arguments       | `-sV --top-ports 20 -T4`  | Custom flags passed to Nmap for each host      |
| Nmap Top Ports       | 20 (fast)                 | Quick select: 20, 100, 500, or 1000 ports      |
| Probe Timeout (s)    | 5                         | Timeout per deep probe (HTTP, SSL, banner)     |
| SSDP Timeout (s)     | 4                         | Wait time for UPnP multicast discovery         |
| HTTP/HTTPS probing   | On                        | Server header, page title, redirect chain      |
| SSL/TLS analysis     | On                        | Certificate subject, issuer, validity, SANs    |
| TCP banner grabbing  | On                        | Raw banners from SSH, FTP, SMTP, MySQL, etc.   |
| SSDP / UPnP discovery| On                       | Multicast M-SEARCH for smart devices           |
| MAC vendor lookup    | On                        | OUI database resolves MAC to manufacturer      |

### Display
| Setting                   | Default | Description                            |
|---------------------------|---------|----------------------------------------|
| Auto-scroll to new results | On      | Scroll to latest online host in grid   |
| Show offline hosts in grid | On      | Show/hide offline blocks in grid view  |
| Enable animations          | On      | Toggle all CSS animations              |

### Notifications
| Setting                | Default | Description                             |
|------------------------|---------|-----------------------------------------|
| Show toast notifications | On     | Show popup notifications for events     |
| Sound on scan complete  | Off     | Play a beep when scan finishes          |

### Live Update
| Setting            | Default  | Options                          | Description                                    |
|--------------------|----------|----------------------------------|------------------------------------------------|
| Update Interval    | 1 minute | 30s, 1min, 2min, 5min, 10min     | Wait time after each completed ping round      |
| Pings per Host     | 2        | 1 to 5                           | Pings per host per cycle (higher = more reliable) |

---

## Architecture

```
+-----------------------------------------------------+
|                   Browser (Client)                   |
|  +----------+  +----------+  +------------------+   |
|  | Grid View|  | List View|  | Host Detail Modal|   |
|  +----+-----+  +----+-----+  +--------+---------+   |
|       +--------------+----------------+              |
|                      |                               |
|              Socket.IO (WebSocket)                   |
+----------------------+-------------------------------+
                       |
+----------------------+-------------------------------+
|                  Flask Server (app.py)                |
|  +--------------------------------------------------+|
|  |              SocketIO Event Handlers              ||
|  | start_scan | stop_scan | batch_full_scan | live   ||
|  +-----+------+-----+----+-------+---------+---+----+|
|        |             |            |             |     |
|  +-----v-----+ +----v---+ +------v------+ +----v--+ |
|  |ping_sweep | | config | | deep_scan   | | nmap  | |
|  |(parallel) | |  .py   | | (HTTP, SSL, | |scanner| |
|  +-----+-----+ +--------+ |  banners,   | +---+---+ |
|        |                   |  SSDP, ARP, |     |     |
|        |                   |  MAC vendor)| +---+---+ |
|  +-----v-------------------+------+------+ |host_  | |
|  |          System Commands (subprocess)   ||info   | |
|  |   ping . nmap . nbtstat . arp           |+-------+ |
|  +-----------------------------------------+          |
+-------------------------------------------------------+
```

### Data Flow

1. **Quick Sweep**: Client emits `start_scan` (with ping timeout + threads from Settings) > Flask spawns `ping_sweep()` > streams `host_result` per host in real-time.
2. **Full Scan**: After ping sweep completes, auto-triggers `batch_full_scan` (with all probe toggles from Settings):
   - **Phase 1  L2 Discovery**: SSDP multicast + full ARP table read (once for entire subnet)
   - **Phase 2  Per-host**: Nmap scan (configurable args) + enabled deep probes with pre-gathered L2 data
   
   > **Smart sweep skip:** If a Quick Sweep was already completed and results are available, clicking Full Scan skips the redundant ping sweep and goes straight to the deep scan phase.
3. **Live Update**: Client periodically emits `live_update` > server re-pings all IPs in parallel > streams results.
4. **Host Detail**: Click a host > `scan_host_detail` > server runs `get_full_host_info()` (DNS, NetBIOS, ARP, WHOIS) + Nmap full scan (top 1000 ports, `-sV -sC`, `-O -A` if admin) + deep probes > emits combined result. Response time is merged from cached ping data.

---

## Project Structure

```
subnet-scanner/
+-- app.py                 # Flask application & SocketIO event handlers
|                          # Routes: / (dashboard), /api/host/<ip>
|                          # Events: start_scan, stop_scan, batch_full_scan,
|                          #         live_update, scan_host_detail
|
+-- config.py              # Configuration (threads, timeouts, nmap args)
+-- requirements.txt       # Python dependencies
+-- start.bat              # Windows auto-setup (venv + deps + launch)
|
+-- scanner/               # Backend scanning modules
|   +-- __init__.py
|   +-- ping_sweep.py      # Parallel ICMP ping sweep with TTL OS guessing
|   +-- nmap_scanner.py    # Nmap wrapper: quick_scan, full_scan, scan_host
|   |                      # Auto --unprivileged on Windows without admin
|   +-- host_info.py       # DNS, NetBIOS (nbtstat/nmblookup), ARP, WHOIS
|   +-- deep_scan.py       # HTTP/HTTPS probe, SSL cert analysis,
|                          # TCP banner grab, SSDP/UPnP discovery,
|                          # full ARP table scan, MAC vendor lookup (OUI)
|
+-- templates/
|   +-- base.html          # Base layout: navbar, settings modal, footer
|   +-- index.html         # Main page: scan controls, stats, grid/list,
|                          # toolbar, host detail modal
|
+-- static/
    +-- css/
    |   +-- custom.css     # Complete dark theme (1400+ lines)
    +-- js/
        +-- scanner.js     # Frontend controller (1750+ lines)
                           # WebSocket, state, grid/list rendering,
                           # DataTable (with natural IP sort),
                           # live update, host detail modal,
                           # well-known port names, comprehensive
                           # host detail rendering
```

---

## How It Works

### 1. Quick Sweep (Ping Sweep)

Enter a subnet in CIDR notation (e.g. `192.168.1.0/24`) and click **Quick Sweep** or press `Ctrl+Enter`.

The backend runs a parallel ICMP ping sweep using `ThreadPoolExecutor`. Each result is streamed to the browser in real-time  hosts appear as they respond, not after the full sweep completes. TTL values are parsed to immediately show an OS family guess (Linux/Windows/Network Device). Ping timeout and thread count are configurable in Settings.

A `/24` subnet (254 hosts) typically completes in 3-8 seconds.

### 2. Full Scan (Ping + Nmap + Deep Probes)

Click **Full Scan** to run the complete scanning pipeline:

1. **Ping sweep**  same as Quick Sweep, discovers online/offline hosts. **Skipped if a sweep was already completed** — the Full Scan goes directly to deep scan using existing results.
2. **L2 discovery**  SSDP multicast and full ARP table read (once for entire subnet)
3. **Per-host deep scan**  For each online host in parallel:
   - Nmap port scan (configurable arguments and port count via Settings)
   - HTTP/HTTPS probing (server, title, headers)
   - SSL/TLS certificate analysis
   - TCP banner grabbing
   - MAC vendor lookup via OUI database

Each probe can be individually enabled/disabled in Settings. Timeouts for deep probes and SSDP discovery are also configurable. Results stream into the list view in real-time.

### 3. View Results

- **Grid View**: Compact color-coded blocks. Green = online, red/grey = offline.
- **List View**: Searchable, sortable table. After Full Scan, shows open ports, OS, MAC, and vendor info.

### 4. Live Update

Toggle **Live Update** to continuously re-ping all discovered hosts. Configurable intervals (30s to 10min). Each round completes before the next starts.

### 5. Host Detail

Click any host to open the detail modal. Runs a full Nmap scan (top 1000 ports, `-sV -sC`) + deep scan probes + WHOIS lookup automatically. The modal shows everything collected:

- **Basic info** — IP, status, hostname, response time, reverse DNS, MAC (styled code block), vendor (OUI), NetBIOS, workgroup
- **All hostnames** — Full nmap hostname array with type labels (PTR, user, etc.)
- **UPnP / SSDP** — Server, location, services list
- **DNS** — DNS names, PTR records
- **OS detection** — Up to 5 matches with accuracy, plus OS classes (type, vendor, family, generation, CPE)
- **Ports & services table** — Port (with protocol name tags), proto, state, service, product, version, extra info. Expandable per-port CPE identifiers and NSE script output inline.
- **HTTP info** — Status code, server, powered-by, page title, content-type, redirect, full response headers (with port indicator)
- **HTTPS info** — Same as HTTP but for HTTPS connections (separate section)
- **SSL/TLS certificate** — Protocol, cipher, subject, issuer, validity dates, SANs (with port indicator)
- **Service banners** — Raw TCP banners with protocol names for known ports
- **NSE host scripts** — Host-level nmap script output
- **System info** — Uptime (human-readable ‘d h m’ format + raw seconds), last boot, TCP sequence prediction (class, difficulty, index, values)
- **WHOIS** — Raw WHOIS data in scrollable panel
- **Error notices** — Inline alerts for scan errors or limited data warnings

---

## API Reference

### REST Endpoints

#### `GET /`
Main dashboard page.

#### `GET /api/host/<ip>`
Host information (DNS, NetBIOS, ARP) without Nmap.

#### `POST /api/host/<ip>/scan`
Nmap scan on a single host. Body: `{ "scan_type": "quick" | "full" }`

### WebSocket Events

#### Client > Server

| Event              | Payload                                    | Description                           |
|--------------------|--------------------------------------------|---------------------------------------|
| `start_scan`     | `{ subnet, scan_id, ping_timeout, threads }` | Begin ping sweep with settings      |
| `stop_scan`      | `{ scan_id }`                           | Stop active scan                      |
| `batch_full_scan`| `{ ips, nmap_args, deep_timeout, ssdp_timeout, deep_http, deep_ssl, deep_banners, deep_ssdp, deep_mac_vendor }` | Nmap + deep scan with probe toggles |
| `batch_nmap_scan`| `{ ips: [...] }`                        | Nmap only on all listed IPs           |
| `stop_batch_scan`| `{}`                                    | Stop running batch scan               |
| `live_update`    | `{ ips: [...], ping_count: 2 }`         | Re-ping listed IPs                    |
| `scan_host_detail`| `{ ip, scan_type }`                    | Detailed host scan                    |

#### Server > Client

| Event                       | Description                            |
|-----------------------------|----------------------------------------|
| `connected`               | Connection confirmed                   |
| `scan_started`            | Ping sweep begun                       |
| `host_result`             | Single host ping result                |
| `scan_complete`           | Ping sweep finished                    |
| `scan_error`              | Scan error                             |
| `scan_stopped`            | Scan stopped by user                   |
| `batch_full_scan_result`  | Per-host deep scan result              |
| `batch_full_scan_progress`| Deep scan progress (done/total/phase)  |
| `batch_full_scan_complete`| All deep scans finished                |
| `batch_nmap_result`       | Per-host nmap result                   |
| `batch_nmap_progress`     | Nmap batch progress                    |
| `batch_nmap_complete`     | All nmap scans finished                |
| `live_update_result`      | Single host re-ping result             |
| `live_update_progress`    | Live update cycle progress             |
| `live_update_complete`    | Live update cycle finished             |
| `host_detail_scanning`    | Detail scan started                    |
| `host_detail_result`      | Detail scan complete                   |
| `host_detail_error`       | Detail scan failed                     |

---

## Keyboard Shortcuts

| Shortcut       | Action              |
|----------------|----------------------|
| `Ctrl+Enter` | Start scan           |
| `Escape`     | Stop active scan     |
| `F11`        | Toggle fullscreen    |

---

## Troubleshooting

### Nmap not found or no port data
- Ensure Nmap is installed and in your system PATH: `nmap --version`
- On Windows, restart your terminal after installing Nmap.

### UAC / admin popup on Windows
- This should **not** happen. The scanner uses `--unprivileged` mode automatically on Windows.
- If you still see popups, check if another application is triggering them.
- Running as admin is optional and only needed for OS detection (`-O`) and SYN scans.

### OS detection returns empty
- OS detection (`-O`) requires admin/sudo privileges.
- Without elevation, the TTL-based OS guess is used as a fallback (shown with a `?` icon).

### Scan is slow
- Increase `MAX_THREADS` in `config.py` or via environment variable.
- Use a smaller subnet for testing (e.g. `/28`).
- Full Scan is slower because it runs Nmap + deep probes on each host.

### Live Update shows inconsistent results
- Increase **Pings per Host** in Settings (default 2, max 5).
- Increase **Update Interval** to reduce network load.

### WebSocket disconnects
- Check that no firewall blocks WebSocket on port 5000.
- Refresh the browser. Connection status is shown in the navbar.

### `eventlet` import errors on Python 3.13+
- Expected. The app uses `async_mode="threading"`  eventlet is not required.

### `start.bat` doesn't work
- Windows only. Ensure Python and Nmap are in PATH.
- On Linux/macOS, use the manual setup instructions.

### Missing NetBIOS / ARP info
- Windows: `nbtstat` is built-in. ARP uses `arp -a` (built-in).
- Linux: Install `samba-common` for NetBIOS: `sudo apt install samba-common`

---

## Security Considerations

- **Only scan networks you own or have permission to scan.** Network scanning may trigger IDS/IPS alerts.
- **Designed for local/development use.** Binds to `0.0.0.0:5000`  accessible to anyone on the same network.
- **Change `SECRET_KEY`** in `config.py` before exposing to a network.
- **Do not expose to the public internet** without proper authentication and HTTPS.
- **Deep scans can be intrusive.** NSE scripts (`-sC`) actively probe services.
- **Running as admin** grants significant network privileges. Only elevate when needed.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and test
4. Commit: `git commit -m "Add my feature"`
5. Push: `git push origin feature/my-feature`
6. Open a Pull Request

### Development Setup

```bash
git clone https://github.com/jop97/subnet-scanner.git
cd subnet-scanner
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python app.py
```

Debug mode is enabled by default  the server auto-reloads on file changes.

---

## License

MIT
