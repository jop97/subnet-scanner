# Subnet Scanner v1.2.0

A real-time network scanning web application built with Flask, Socket.IO, and Nmap. Discover hosts on your network with a clean dark UI featuring a visual IP grid, live status updates, and detailed host information.

![Version](https://img.shields.io/badge/Version-1.2.0-cyan)
![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Table of Contents

- [Features](#features)
- [Scan Profiles](#scan-profiles)
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
| **Full Scan** | Ping sweep **+** Nmap port/service scan **+** MAC/vendor lookup on every online host. Runs automatically in sequence: ping > nmap > ARP/MAC vendor. The detail modal performs the full deep scan (HTTP/SSL/banners/SSDP) independently when opened. |

### Full Scan Probes (table columns)
- **Nmap port & service detection**  Top 20 ports with version fingerprinting (`-sV`)
- **MAC vendor lookup**  OUI database resolves MAC addresses to manufacturer names (e.g. `Intel Corporate`, `Apple, Inc.`)
- **Full ARP table scan**  Reads all known MACs on the network in one call before per-host scanning
- **TTL-based OS guessing**  Immediate OS family guess (Linux/Windows/Network Device) from ping TTL

### Detail Modal Probes (full deep scan)
The detail modal always runs a complete independent scan with all probes:
- **Nmap full scan**  Top 2500 ports (configurable: 1000-10000) with service/version detection, real-time port progress
- **HTTP/HTTPS probing**  Server header, page title, redirect chain, security headers (separate sections for HTTP and HTTPS)
- **SSL/TLS certificate analysis**  Subject, issuer, validity dates, SANs, cipher suite, port indicator
- **TCP banner grabbing**  Raw banners from SSH, FTP, SMTP, MySQL, RDP, and more
- **MAC vendor lookup**  OUI database resolves MAC addresses to manufacturer names
- **SSDP/UPnP discovery**  Multicast M-SEARCH finds smart devices, routers, IoT, media servers
- **WHOIS lookup**  Basic WHOIS information for the IP address
- **DNS / NetBIOS**  Reverse DNS, NetBIOS name and workgroup resolution
- **SSH host key**  Banner and key type fingerprinting for SSH servers (port 22)
- **mDNS / Bonjour**  Queries host's mDNS responder for .local hostname
- **Geolocation**  Country, city, ISP, AS number, coordinates for public IPs (via ip-api.com)

### Host Detail Modal
Click any host for a deep-dive view with a full independent scan (4-phase progress tracker with real-time Nmap port progress):
- **4-phase progress tracker** — DNS/NetBIOS/WHOIS → Nmap scan (configurable ports) → HTTP/SSL/banner probes → Extended discovery (SSH, mDNS, Geo)
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
- **SSH host key** — Banner, key type, and fingerprint for SSH servers
- **mDNS / Bonjour** — .local hostname from mDNS responder
- **Geolocation** — Country, region, city, ISP, organization, AS number, coordinates, timezone (public IPs only)
- **Error & status notices** — Inline alerts for scan errors or limited data

### Views & Filtering
- **Grid View**  Compact color-coded IP grid, sorted by IP. Click any block for full details.
- **List View**  Full-width sortable, searchable table with columns: status, IP, hostname, response time, open ports, OS, MAC/vendor, and action buttons.
- **Filters**  Toggle between All / Online / Offline hosts in both views.

### Live Monitoring
- **Live Update**  Toggle to re-ping all discovered hosts on a schedule. Intervals: 30s, 1min, 2min, 5min, 10min.
- **Status Card**  Real-time state indicator (Idle / Scanning / Live / Done / Error) with progress bar.

### Customization
- **Scan Profiles**  Fast / Normal / Thorough presets for different network conditions. One-click configuration.
- **Settings Modal**  Comprehensive settings organized by category — scan parameters, probe toggles, display preferences, notifications. All persisted in localStorage.
- **Keyboard Shortcuts**  `Ctrl+Enter` to start scan, `Escape` to stop.
- **Fullscreen Mode**  Toggle from the navbar.

---

## Scan Profiles

The Settings modal includes three built-in scan profiles that apply optimized presets for different scenarios:

| Profile      | Ping Timeout | Threads | Sweep Pings | Table Ports | Detail Ports | Timing | Best For |
|--------------|--------------|---------|-------------|-------------|--------------|--------|----------|
| **Fast**     | 500ms        | 100     | 1           | Top 20      | Top 1000     | T5     | Quick network overview, responsive hosts |
| **Normal**   | 1000ms       | 50      | 1           | Top 20      | Top 2500     | T4     | Typical home/office networks (default) |
| **Thorough** | 2000ms       | 25      | 2           | Top 100     | Top 5000     | T3     | Unreliable networks, slow hosts |

Clicking a profile button instantly applies all settings. You can then fine-tune individual values if needed.

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
2. **Kill any existing server on port 5000** (safe restart)
3. Create a `.venv` virtual environment (first run only)
4. Install all dependencies from `requirements.txt`
5. Open your default browser at `http://localhost:5000`
6. Start the Flask development server

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

> **Note:** Nmap arguments are now configured via the Settings modal (port count, timing template). The old `DEFAULT_NMAP_ARGS` config option was removed in v1.1.5.

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

The Settings modal (gear icon in the navbar) provides runtime configuration organized into clear sections. All settings are **persisted in localStorage** and applied immediately. Click **Reset** to restore defaults.

### Scan Profile
One-click presets that configure multiple settings at once. See [Scan Profiles](#scan-profiles) for details.

### Quick Sweep
| Setting            | Default | Description                                    |
|--------------------|---------|------------------------------------------------|
| Ping Timeout (ms)  | 1000    | Maximum wait time per host ping                |
| Concurrent Threads | 50      | Number of parallel scan threads                |
| Pings per Host     | 1       | ICMP pings during sweep (1 = fastest)          |

### Full Scan (Table)
Settings for batch scanning all online hosts to populate the table view.

| Setting              | Default | Options           | Description                                    |
|----------------------|---------|-------------------|------------------------------------------------|
| Top Ports            | 20      | 20, 50, 100, 200  | Number of ports per host in batch scan         |
| Nmap Timing          | T4      | T3, T4, T5        | Nmap timing template (T5 = fastest)            |

### Detail Modal
Settings for the in-depth scan when opening a host's detail view.

| Setting              | Default | Options                     | Description                                    |
|----------------------|---------|-----------------------------|------------------------------------------------|
| Top Ports            | 2500    | 1000, 2500, 5000, 10000     | Number of ports for detail scan                |
| Host Timeout (s)     | 180     | 60 - 600                    | Max time for nmap to scan a single host        |

### Deep Probes
Additional probes run after the nmap scan in detail view.

| Setting              | Default | Description                                    |
|----------------------|---------|------------------------------------------------|
| Probe Timeout (s)    | 5       | Timeout per probe (HTTP, SSL, banner)          |
| SSDP Timeout (s)     | 4       | Wait time for UPnP multicast discovery         |
| HTTP/HTTPS probing   | On      | Server header, page title, redirect chain      |
| SSL/TLS analysis     | On      | Certificate subject, issuer, validity, SANs    |
| TCP banner grabbing  | On      | Raw banners from SSH, FTP, SMTP, MySQL, etc.   |
| SSDP / UPnP discovery| On      | Multicast M-SEARCH for smart devices           |
| MAC vendor lookup    | On      | OUI database resolves MAC to manufacturer      |

### Extended Discovery
Additional fingerprinting and info gathering probes (Phase 4).

| Setting                  | Default | Description                                    |
|--------------------------|---------|------------------------------------------------|
| SSH host key fingerprint | On      | Extract SSH banner and key type from port 22   |
| mDNS / Bonjour discovery | On      | Query mDNS for .local hostname                 |
| Geolocation (public IPs) | On      | Country, city, ISP, AS number via ip-api.com   |

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
4. **Host Detail**: Click a host > `scan_host_detail` > server runs `get_full_host_info()` (DNS, NetBIOS, ARP, WHOIS) + Nmap full scan (configurable ports, default 2500, `-sV`, `-O -A` if admin) + deep probes > emits combined result. Response time is merged from cached ping data.

---

## Project Structure

```
subnet-scanner/
+-- app.py                 # Flask application & SocketIO event handlers (~445 lines)
|                          # Routes: / (dashboard), /api/host/<ip>
|                          # Events: start_scan, stop_scan, batch_full_scan,
|                          #         live_update, scan_host_detail
|
+-- config.py              # Configuration (threads, timeouts)
+-- requirements.txt       # Python dependencies
+-- start.bat              # Windows auto-setup (venv + deps + launch)
|                          # Auto-kills existing server on port 5000
|
+-- scanner/               # Backend scanning modules
|   +-- __init__.py
|   +-- ping_sweep.py      # Parallel ICMP ping sweep with TTL OS guessing
|   +-- nmap_scanner.py    # Nmap wrapper: quick_scan, full_scan, scan_host (~315 lines)
|   |                      # Auto --unprivileged on Windows without admin
|   +-- host_info.py       # DNS, NetBIOS (nbtstat/nmblookup), ARP, WHOIS
|   +-- deep_scan.py       # HTTP/HTTPS probe, SSL cert analysis, (~535 lines)
|                          # TCP banner grab, SSDP/UPnP discovery,
|                          # full ARP table scan, MAC vendor lookup (OUI)
|
+-- templates/
|   +-- base.html          # Base layout: navbar, settings modal, footer (~290 lines)
|                          # Settings modal with profile selector
|   +-- index.html         # Main page: scan controls, stats, grid/list,
|                          # toolbar, host detail modal
|
+-- static/
    +-- css/
    |   +-- custom.css     # Complete dark theme (~1560 lines)
    |                      # Profile button styles, toggle switches
    +-- js/
        +-- scanner.js     # Frontend controller (~2050 lines)
                           # WebSocket, state, grid/list rendering,
                           # DataTable (with natural IP sort),
                           # profile presets, settings management,
                           # live update, host detail modal
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

Click any host to open the detail modal. Runs a full Nmap scan (configurable ports, default 2500) + deep scan probes + WHOIS lookup automatically. The modal shows everything collected:

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
| `batch_full_scan`| `{ ips, top_ports, timing, deep_timeout, ssdp_timeout, deep_http, deep_ssl, deep_banners, deep_ssdp, deep_mac_vendor }` | Nmap + deep scan with settings |
| `batch_nmap_scan`| `{ ips: [...] }`                        | Nmap only on all listed IPs           |
| `stop_batch_scan`| `{}`                                    | Stop running batch scan               |
| `live_update`    | `{ ips: [...], ping_count: 2 }`         | Re-ping listed IPs                    |
| `scan_host_detail`| `{ ip, top_ports, host_timeout, deep_timeout, ssdp_timeout, deep_http, deep_ssl, deep_banners, deep_ssdp, deep_mac_vendor }` | Detailed host scan with settings |

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
| `host_detail_progress`    | Detail scan phase progress (phase/total/label) |
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

## Changelog

### v1.2.0

**Extended Discovery (Phase 4)**
- Added new Extended Discovery phase to detail modal scans (4 phases total)
- **SSH Host Key Fingerprint** — Extracts SSH banner and key type from port 22
- **mDNS / Bonjour Discovery** — Queries host's mDNS responder for .local hostname
- **Geolocation** — IP-based location lookup for public IPs (country, city, ISP, AS, coordinates)
- All three probes are toggleable in Settings → Extended Discovery
- New settings section with dedicated icon (`fa-satellite`)

**Settings & Configuration**
- Deep probes now enabled by default: HTTP, SSL, TCP Banners, SSDP, MAC Vendor
- Extended discovery probes enabled by default: SSH, mDNS, Geolocation
- Fixed `nmapTiming` format bug (was sending `T4` instead of `-T4`)
- Fixed `sweepPingCount` not being sent to backend
- Dynamic nmap timeout based on timing template (T5=30s, T4=60s, T3=90s, T2=120s, T1=150s)

**Full Scan Flow Fix**
- Fixed critical bug where Full Scan only performed sweep, not the deep scan phase
- Root cause: `clearResults()` was resetting `fullScanPending` flag before scan started
- Full Scan now correctly runs: sweep → clear old results → deep scan all online hosts

**UI Improvements**
- Detail modal loading indicator now shows 4 phases with descriptive labels
- Phase 4 icon: `fa-satellite` for extended discovery
- Cache version bumped to v=25 for fresh asset loading

**Backend Improvements**
- New probe functions in `deep_scan.py`:
  - `get_ssh_host_key(ip, port, timeout)` — SSH banner and host key extraction
  - `get_mdns_info(ip, timeout)` — mDNS PTR record lookup via unicast DNS
  - `get_geolocation(ip, timeout)` — ip-api.com lookup for public IPs
  - `is_private_ip(ip)` — RFC1918/loopback/link-local detection
- `ping_sweep()` now accepts `count` parameter for configurable pings per host

### v1.1.7

**UI Fixes**
- Fixed missing icon on Fast profile button (was using non-existent `fa-rabbit`, now uses `fa-bolt`)

**Default Settings**
- SSL/TLS certificate analysis now disabled by default (faster scans)
- TCP banner grabbing now disabled by default
- SSDP/UPnP discovery now disabled by default
- These can be enabled in Settings → Deep Probes when needed

### v1.1.6

**Scan Profiles**
- Added scan profile selector (Fast / Normal / Thorough) at the top of the Settings modal
- Profiles apply preset values for ping timeout, threads, port counts, nmap timing, and probe timeouts
- **Fast**: 500ms timeout, 100 threads, top 20 ports (table), top 1000 ports (detail), T5 timing
- **Normal**: 1000ms timeout, 50 threads, top 20 ports (table), top 2500 ports (detail), T4 timing
- **Thorough**: 2000ms timeout, 25 threads, top 100 ports (table), top 5000 ports (detail), T3 timing

**Settings Modal Redesign**
- Reorganized settings into clear sections: Scan Profile, Quick Sweep, Full Scan (Table), Detail Modal, Deep Probes, Display, Notifications, Live Update
- Added separate port count settings for batch table scan vs detail modal scan
- Detail modal now defaults to 2500 ports (configurable: 1000 / 2500 / 5000 / 10000)
- Added "Pings per Host" setting for quick sweep (1-5)
- Added "Host Timeout" setting for detail modal (60-600 seconds)
- Added "Nmap Timing" selector (T3/T4/T5) for batch full scan
- Removed the raw "Nmap Arguments" text field — now using structured dropdowns
- Modal is now larger (`modal-lg`) and scrollable for better UX

**Backend Changes**
- `full_scan_with_progress()` now accepts `top_ports` and `host_timeout` parameters
- `scan_host_detail` WebSocket handler accepts all deep probe settings from client
- Detail scan respects per-probe toggles (HTTP, SSL, banners, SSDP, MAC vendor)
- Footer updated to 2026

### v1.1.5

**Detail Modal Hang Fix**
- Added `--host-timeout 120s` to the detail modal nmap scan to prevent indefinite hangs on unresponsive hosts
- Added heartbeat thread during Phase 2 (nmap scan) — emits periodic progress events when nmap is silent, keeping the frontend informed
- Added client-side 3-minute timeout: if no progress events arrive for 3 minutes, the scan is marked as timed out with a user-friendly error message
- Timeout resets on every progress event, so long-running scans that report progress are not killed prematurely
- Stale result filtering: `host_detail_result` and `host_detail_error` events now check the IP matches the currently open modal, discarding results from previously opened hosts
- `--stats-every` interval increased from 1s to 2s to reduce progress event noise
- Improved subprocess cleanup in `full_scan_with_progress()`: `proc.stdout.close()` in reader thread `finally` block, `proc.wait(timeout=10)` after `proc.kill()` to avoid zombie processes
- Partial results are now returned on timeout (nmap XML may contain partial data)
- Modal close event (`hidden.bs.modal`) clears the client-side timeout

**REST API `-Pn` Fix**
- `scan_host()` default arguments now include `-Pn` (was missing from default, affecting REST API calls)
- REST API `/api/host/<ip>/scan` endpoint now injects `-Pn` into custom `nmap_args` when not already present
- Ensures consistent host-discovery behaviour across all scan paths (WebSocket + REST)

**Dependency & Config Cleanup**
- Removed unused `eventlet` from `requirements.txt` — the app uses `async_mode="threading"`, eventlet was never imported
- Removed unused `DEFAULT_NMAP_ARGS` from `config.py` — was never referenced anywhere in the codebase

### v1.1.4

**Nmap Host Discovery Fix**
- Added `-Pn` (skip host discovery) to all nmap scan functions: `quick_scan()`, `full_scan()`, `full_scan_with_progress()`, and `batch_full_scan`
- Fixes a critical issue where nmap's TCP-based host discovery (ports 80/443) would fail on hosts that respond to ICMP ping but block those TCP ports, resulting in "host not found" and empty scan results
- Since the ping sweep already confirmed hosts are alive, nmap's redundant host discovery phase is safely skipped

**Deep Probe Fallback on Common Ports**
- When nmap returns zero open ports, deep scan probes now try common ports instead of skipping entirely
- HTTP probes fall back to ports 80, 8080, 8000, 8888
- HTTPS probes fall back to ports 443, 8443
- SSL certificate probes fall back to ports 443, 8443
- Banner grabbing falls back to ports 22, 21, 25, 80, 443, 3389, 8080
- Ensures the detail modal shows useful information even when nmap can't detect ports (e.g. firewall-filtered hosts)

**SSDP Discovery in Detail Modal**
- SSDP/UPnP multicast discovery now runs during the detail modal scan (Phase 2, background thread during nmap)
- Previously SSDP was only available in batch full scans, detail modal had no SSDP data

**HTTP/SSL Port Expansion from Nmap Services**
- `deep_scan_host()` now accepts `nmap_services` parameter
- HTTP probe ports are dynamically expanded when nmap detects HTTP services on non-standard ports
- SSL probe ports are dynamically expanded when nmap detects SSL/TLS services on non-standard ports
- Web interfaces on unusual ports (e.g. management consoles on port 9090) are now discovered

**Code Quality**
- Moved `import threading` to module level in app.py
- Fixed copyright year in footer (2026 → 2025)

### v1.1.3

**start.bat — Auto-kill existing server**
- `start.bat` now checks if port 5000 is already in use before starting
- Automatically kills the existing server process (via `netstat` + `taskkill`)
- Safe to double-click `start.bat` without manually stopping the previous instance

**Code Quality & Cleanup**
- Removed dead `get_ttl_os_guess()` function from deep_scan.py (duplicate of ping_sweep's `_ttl_os_guess()`)
- Moved `shutil` import to module level in host_info.py (was re-imported on every WHOIS call)
- Fixed duplicate `8443: 'HTTPS-Alt'` entry in the well-known ports map
- Fixed memory growth: `scan_results` dict now clears stale entries on new scan
- Fixed changelog reference: nmap progress uses stdout, not stderr

### v1.1.2

**Full Scan Optimization**
- Removed deep scan probes (HTTP, SSL, banners, SSDP) from the batch full scan — only nmap + MAC/vendor is needed for the table columns
- Significantly faster full scan completion time
- Detail modal always performs a complete independent scan with all probes when opened

**Nmap Port Progress in Detail Modal**
- Detail modal now shows real-time nmap port progress (~N/1000 ports) during phase 2
- Uses `--stats-every 1s` subprocess with stdout parsing for live progress updates
- Progress bar interpolates smoothly within each scan phase
- New `full_scan_with_progress()` function in nmap_scanner.py

**Sweep Progress Fix**
- Fixed progress stat card jumping backward during sweep (hosts returned out of order from `as_completed`)
- Progress is now monotonic — percentage only goes up, never back
- Eliminated double progress bar updates (was set by both `updateStats` and explicit `progressFill`)
- Clean status transitions: Sweeping → Sweep N% → Sweep done — starting deep scan → Deep Scan N/M → Done

**Live Update Data Preservation**
- Live update no longer overwrites ports, OS, and MAC/vendor columns from full scan
- Only status badge, response time, and hostname are updated during live pings
- Full scan data in the table persists across all live update cycles

**UI Polish**
- Table row borders softened (`border-top: none` to override Bootstrap's bright `#dee2e6`)
- L2 discovery phase label shown during deep scan init (was "Deep Scan 0/N")
- Deep scan progress bar resets to 0% properly at start

### v1.1.1

**Detail Modal — Scan Progress Indicator**
- Added 3-phase progress tracker in the detail modal loading screen
- Each phase shows real-time status: pending → active (pulsing) → completed (checkmark)
- Phases: DNS/NetBIOS/WHOIS → Nmap scan → HTTP/SSL/banner probes
- Animated progress bar tracks overall scan progress
- Quick info view (cached ping data) also shows the progress steps below

**Ping Response Time Fix**
- Fixed response time parsing for `time<1ms` on Windows (common for fast LAN pings)
- Previous regex failed on `time<1ms` and fell back to subprocess elapsed time (20-100ms+ overhead)
- New locale-independent regex handles `time=5ms`, `time<1ms`, `tijd=0.5ms` (Dutch), etc.
- Timer now starts immediately before subprocess.run, not at function entry

**MAC Vendor Optimization**
- Detail modal now passes MAC address from phase 1/2 to phase 3, eliminating redundant ARP call
- Previously `arp -a` was called twice: once in host_info (phase 1) and again in deep_scan (phase 3)

**Code Quality**
- Added `CREATE_NO_WINDOW` subprocess flag to ping_sweep.py for Windows consistency
- Removed unused `scan_type` parameter from detail scan handler
- All subprocess calls now consistently suppress console windows on Windows

### v1.1.0

**Host Detail Modal — Comprehensive Data Display**
- Added separate HTTPS info section (previously only HTTP was shown)
- Added TCP sequence prediction display (class, difficulty, index, values)
- Added OS classes inside OS detection (type, vendor, family, generation, CPE)
- Added CPE identifiers per service in the port table
- Added per-port NSE script output inline in the port table
- Added all nmap hostnames with type labels (PTR, user, etc.)
- Added port indicators on HTTP/HTTPS/SSL section headers
- Added WHOIS information panel (scrollable raw WHOIS data)
- Added response time from cached ping data in basic info
- Added human-readable uptime format (e.g. "2d 5h 30m")
- Added protocol names on service banner labels (e.g. "Port 22 (SSH)")
- Error messages are now HTML-escaped for safety

**Smart Sweep Skip**
- Full Scan now skips the ping sweep when results from the same subnet are already available
- Different subnet always triggers a fresh sweep first

**UI Improvements**
- Grid blocks: fixed first-row height stretch, blocks now have consistent height
- Grid blocks: increased text size for better readability
- Grid blocks: slightly wider minimum width (86px)
- List view: softened table row borders for lower contrast
- List view: natural IP address sorting (numeric octets, matching grid view order)
- Added `--text-secondary` CSS variable for consistent text colors
- Footer updated with version number and feature tags

**Backend**
- `get_full_host_info()` now includes WHOIS lookup
- Detail modal runs configurable Nmap scan (default 2500 ports, configurable timeout)
- Refactored HTTP rendering into shared `renderHttpSection()` helper

**Documentation**
- Comprehensive README update with all new features documented
- Updated architecture diagrams and data flow descriptions
- Added version badge

### v1.0.0

- Initial release
- Ping sweep, Nmap scanning, deep scan probes
- Grid & list views with filtering
- Real-time Socket.IO updates
- Settings modal with localStorage persistence
- Live update monitoring
- Host detail modal
- Dark theme UI

---

## License

MIT
