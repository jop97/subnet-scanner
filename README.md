# Subnet Scanner

A hyper-modern network scanning web application built with Flask, AdminLTE, and Nmap. Think Angry IP Scanner — but as a beautiful, real-time web app with a glassmorphism dark UI.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Ping Sweep** — Scan any subnet (CIDR) with real-time results via WebSocket
- **Grid View** — Visual IP grid with color-coded online/offline status blocks
- **List View** — Sortable, searchable DataTable with hostname, response time, ports, OS info
- **Host Detail Modal** — Click any host for deep-dive info:
  - Nmap port & service scan (version detection)
  - OS fingerprinting
  - DNS / reverse DNS / PTR records
  - MAC address & vendor lookup
  - NetBIOS name resolution
  - NSE script results
  - Uptime estimation
- **Real-time updates** — Socket.IO pushes each result as it completes
- **Filters** — Toggle between All / Online / Offline hosts
- **Keyboard shortcuts** — `Ctrl+Enter` to scan, `Escape` to stop

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Flask, Flask-SocketIO, eventlet |
| Scanner | python-nmap, subprocess (ping), dnspython |
| Frontend | AdminLTE 3, Bootstrap 4, Socket.IO, DataTables |
| Styling | Custom glassmorphism dark theme |

## Quick Start

### Prerequisites

- Python 3.10+
- nmap installed (`sudo apt install nmap`)

### Installation

```bash
# Clone the repository
git clone https://github.com/jop97/subnet-scanner.git
cd subnet-scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application (sudo recommended for full nmap features)
sudo .venv/bin/python app.py
```

Open **http://localhost:5000** in your browser.

### Why sudo?

Running with `sudo` enables:
- OS detection (`-O` flag)
- SYN scan (`-sS` flag)
- MAC address detection on local network

Without sudo, the app still works but with reduced nmap capabilities.

## Project Structure

```
├── app.py                 # Flask application & SocketIO events
├── config.py              # Configuration (threads, timeouts, etc.)
├── requirements.txt       # Python dependencies
├── scanner/
│   ├── ping_sweep.py      # Parallel ping sweep engine
│   ├── nmap_scanner.py    # Nmap integration (quick/full scan)
│   └── host_info.py       # DNS, NetBIOS, ARP info gathering
├── templates/
│   ├── base.html          # AdminLTE base layout
│   └── index.html         # Main dashboard page
└── static/
    ├── css/custom.css      # Custom dark glassmorphism theme
    └── js/scanner.js       # Frontend controller (WebSocket, UI)
```

## License

MIT
