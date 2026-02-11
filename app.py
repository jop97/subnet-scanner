"""
Subnet Scanner v1.1.7 — Flask Application
A modern network scanning web application.
"""

import ipaddress
import time
import threading
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from config import Config
from scanner.ping_sweep import ping_sweep, _ping_host
from scanner.nmap_scanner import scan_host, quick_scan, full_scan, full_scan_with_progress
from scanner.host_info import get_full_host_info
from scanner.deep_scan import deep_scan_host, get_arp_table_full, get_mac_vendor, ssdp_discover

app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Store scan state
active_scans = {}
scan_results = {}


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/api/host/<ip>", methods=["GET"])
def get_host_info(ip):
    """Get detailed host information via REST API."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    info = get_full_host_info(ip)
    return jsonify(info)


@app.route("/api/host/<ip>/scan", methods=["POST"])
def scan_single_host(ip):
    """Run nmap scan on a single host."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400
    scan_type = request.json.get("scan_type", "quick") if request.json else "quick"
    nmap_args = request.json.get("nmap_args") if request.json else None

    if scan_type == "quick":
        result = quick_scan(ip)
    else:
        if nmap_args:
            # Inject -Pn if not already present
            if "-Pn" not in nmap_args and "-pn" not in nmap_args.lower():
                nmap_args = "-Pn " + nmap_args
            result = scan_host(ip, arguments=nmap_args)
        else:
            result = scan_host(ip)

    return jsonify(result)


# ── SocketIO Events ────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "Connected to Subnet Scanner"})


@socketio.on("start_scan")
def handle_start_scan(data):
    """Start a ping sweep scan on the given subnet."""
    subnet = data.get("subnet", "").strip()
    scan_id = data.get("scan_id", subnet)

    if not subnet:
        emit("scan_error", {"error": "No subnet provided"})
        return

    if scan_id in active_scans and active_scans[scan_id]:
        emit("scan_error", {"error": "Scan already in progress for this subnet"})
        return

    # Client-side settings override server defaults
    ping_timeout = data.get("ping_timeout", app.config["PING_TIMEOUT"] * 1000)
    ping_timeout_s = max(1, min(ping_timeout // 1000, 10))  # Convert ms → s, clamp 1-10
    threads = max(1, min(data.get("threads", app.config["MAX_THREADS"]), 500))

    active_scans[scan_id] = True
    scan_results[scan_id] = []

    # Clean up results from previous scans to prevent memory growth
    stale = [k for k in scan_results if k != scan_id]
    for k in stale:
        del scan_results[k]

    def run_scan():
        try:
            socketio.emit("scan_started", {
                "scan_id": scan_id,
                "subnet": subnet,
            })

            def on_result(result):
                if not active_scans.get(scan_id, False):
                    return
                result["scan_id"] = scan_id
                scan_results[scan_id].append(result)
                socketio.emit("host_result", result)

            results = ping_sweep(
                subnet,
                timeout=ping_timeout_s,
                max_threads=threads,
                callback=on_result,
            )

            socketio.emit("scan_complete", {
                "scan_id": scan_id,
                "subnet": subnet,
                "total": len(results),
                "alive": sum(1 for r in results if r["alive"]),
                "dead": sum(1 for r in results if not r["alive"]),
            })

        except ValueError as e:
            socketio.emit("scan_error", {"error": str(e), "scan_id": scan_id})
        except Exception as e:
            socketio.emit("scan_error", {"error": f"Scan failed: {str(e)}", "scan_id": scan_id})
        finally:
            active_scans[scan_id] = False

    socketio.start_background_task(run_scan)


@socketio.on("stop_scan")
def handle_stop_scan(data):
    """Stop an active scan."""
    scan_id = data.get("scan_id")
    if scan_id and scan_id in active_scans:
        active_scans[scan_id] = False
        emit("scan_stopped", {"scan_id": scan_id})


@socketio.on("scan_host_detail")
def handle_scan_host_detail(data):
    """Run a detailed nmap scan on a specific host (via WebSocket)."""
    ip = data.get("ip")

    if not ip:
        emit("host_detail_error", {"error": "No IP provided"})
        return

    # Extract settings from client (with sensible defaults)
    top_ports = data.get("top_ports", 2500)
    host_timeout = data.get("host_timeout", 180)
    deep_timeout = data.get("deep_timeout", 5)
    ssdp_timeout = data.get("ssdp_timeout", 4)
    deep_http = data.get("deep_http", True)
    deep_ssl = data.get("deep_ssl", True)
    deep_banners = data.get("deep_banners", True)
    deep_ssdp = data.get("deep_ssdp", True)
    deep_mac_vendor = data.get("deep_mac_vendor", True)

    emit("host_detail_scanning", {"ip": ip})

    def run_detail_scan():
        scan_active = threading.Event()
        scan_active.set()

        try:
            # Phase 1: Host info (DNS, NetBIOS, ARP, WHOIS)
            socketio.emit("host_detail_progress", {
                "ip": ip, "phase": 1, "total": 3,
                "label": "Gathering DNS, NetBIOS & WHOIS info..."
            })
            host_info = get_full_host_info(ip)

            # Phase 2: Nmap full scan
            socketio.emit("host_detail_progress", {
                "ip": ip, "phase": 2, "total": 3,
                "label": f"Running Nmap scan (top {top_ports} ports)..."
            })

            last_nmap_update = [time.time()]

            def nmap_progress(pct):
                last_nmap_update[0] = time.time()
                ports_est = round(pct / 100 * top_ports)
                socketio.emit("host_detail_progress", {
                    "ip": ip, "phase": 2, "total": 3,
                    "label": f"Nmap scan — ~{ports_est}/{top_ports} ports...",
                    "sub_progress": pct,
                    "ports_done": ports_est,
                    "ports_total": top_ports,
                })

            # Heartbeat: emit periodic updates so the frontend knows we're alive
            # (nmap doesn't always print progress early in the scan)
            def _heartbeat():
                phase_start = time.time()
                while scan_active.is_set():
                    scan_active.wait(timeout=5)
                    if not scan_active.is_set():
                        break
                    # Only emit when nmap hasn't reported recently
                    if time.time() - last_nmap_update[0] >= 4:
                        elapsed = int(time.time() - phase_start)
                        socketio.emit("host_detail_progress", {
                            "ip": ip, "phase": 2, "total": 3,
                            "label": f"Nmap scan in progress... ({elapsed}s)",
                        })

            hb_thread = threading.Thread(target=_heartbeat, daemon=True)
            hb_thread.start()

            # Start SSDP discovery in background (runs during nmap)
            ssdp_result_holder = {}
            def _ssdp_bg():
                if not deep_ssdp:
                    return
                try:
                    ssdp_result_holder.update(ssdp_discover(timeout=ssdp_timeout))
                except Exception:
                    pass
            ssdp_thread = threading.Thread(target=_ssdp_bg, daemon=True)
            ssdp_thread.start()

            nmap_result = full_scan_with_progress(
                ip,
                progress_callback=nmap_progress,
                top_ports=top_ports,
                host_timeout=host_timeout,
            )

            # Stop heartbeat
            scan_active.clear()
            hb_thread.join(timeout=2)

            # Wait for SSDP to finish (max 5 s, usually already done)
            ssdp_thread.join(timeout=5)
            ssdp_info = ssdp_result_holder.get(ip)

            # Phase 3: Deep scan probes (HTTP, SSL, banners, SSDP, MAC)
            open_ports = nmap_result.get("open_ports", [])
            known_mac = (nmap_result.get("mac_address")
                         or host_info.get("mac_from_arp"))
            socketio.emit("host_detail_progress", {
                "ip": ip, "phase": 3, "total": 3,
                "label": "Probing HTTP, SSL, banners & SSDP..."
            })
            deep_result = deep_scan_host(
                ip, open_ports, timeout=deep_timeout,
                ssdp_info=ssdp_info,
                arp_mac=known_mac,
                nmap_services=nmap_result.get("services"),
                probe_http=deep_http,
                probe_ssl=deep_ssl,
                probe_banners=deep_banners,
                probe_mac_vendor=deep_mac_vendor,
            )

            combined = {**host_info, **nmap_result, **deep_result}
            socketio.emit("host_detail_result", combined)

        except Exception as e:
            socketio.emit("host_detail_error", {"error": str(e), "ip": ip})
        finally:
            scan_active.clear()  # Ensure heartbeat stops

    socketio.start_background_task(run_detail_scan)


@socketio.on("batch_nmap_scan")
def handle_batch_nmap_scan(data):
    """Run a quick nmap scan on all online hosts to populate list view info."""
    ips = data.get("ips", [])
    if not ips:
        return

    scan_id = "batch_nmap_scan"
    active_scans[scan_id] = True

    def run_batch():
        from concurrent.futures import ThreadPoolExecutor, as_completed

        total = len(ips)
        done = 0

        def scan_one(ip):
            if not active_scans.get(scan_id, False):
                return {"ip": ip, "error": "Cancelled"}
            try:
                return quick_scan(ip, timeout=30)
            except Exception as e:
                return {"ip": ip, "error": str(e)}

        with ThreadPoolExecutor(max_workers=min(10, total)) as executor:
            futures = {executor.submit(scan_one, ip): ip for ip in ips}
            for future in as_completed(futures):
                result = future.result()
                done += 1
                socketio.emit("batch_nmap_result", result)
                socketio.emit("batch_nmap_progress", {
                    "done": done,
                    "total": total,
                    "progress": round((done / total) * 100, 1),
                })

        active_scans[scan_id] = False
        socketio.emit("batch_nmap_complete")

    socketio.start_background_task(run_batch)


@socketio.on("batch_full_scan")
def handle_batch_full_scan(data):
    """Run nmap scan on all online hosts for table display (ports, OS, MAC).

    Only gathers data shown in the list table. Deep probes (HTTP, SSL,
    banners, SSDP) are skipped here — the detail modal does a full
    independent scan when opened.
    """
    ips = data.get("ips", [])
    if not ips:
        return

    nmap_args = data.get("nmap_args", "-sV --top-ports 20 -T4")
    probe_mac_vendor = data.get("deep_mac_vendor", True)

    scan_id = "batch_full_scan"
    active_scans[scan_id] = True

    def run_batch():
        from concurrent.futures import ThreadPoolExecutor, as_completed

        total = len(ips)
        done = 0

        # Inject -Pn: skip nmap host discovery since ping sweep already
        # confirmed these hosts are alive (prevents false "host not found").
        effective_args = nmap_args
        if "-Pn" not in effective_args and "-pn" not in effective_args.lower():
            effective_args = "-Pn " + effective_args

        # Gather ARP table once for MAC lookups
        socketio.emit("batch_full_scan_progress", {
            "done": 0,
            "total": total,
            "progress": 0,
            "phase": "Reading ARP table...",
        })
        arp_table = get_arp_table_full()

        def scan_one(ip):
            if not active_scans.get(scan_id, False):
                return {"ip": ip, "error": "Cancelled"}
            try:
                nmap_result = scan_host(ip, arguments=effective_args, timeout=30)

                # MAC / vendor from ARP (shown in table)
                mac = arp_table.get(ip) or nmap_result.get("mac_address")
                if mac:
                    nmap_result["mac_from_arp"] = mac
                    if probe_mac_vendor:
                        vendor = get_mac_vendor(mac)
                        if vendor:
                            nmap_result["mac_vendor"] = vendor

                nmap_result["ip"] = ip
                return nmap_result
            except Exception as e:
                return {"ip": ip, "error": str(e)}

        with ThreadPoolExecutor(max_workers=min(10, total)) as executor:
            futures = {executor.submit(scan_one, ip): ip for ip in ips}
            for future in as_completed(futures):
                result = future.result()
                done += 1
                socketio.emit("batch_full_scan_result", result)
                socketio.emit("batch_full_scan_progress", {
                    "done": done,
                    "total": total,
                    "progress": round((done / total) * 100, 1),
                    "phase": "Scanning hosts...",
                })

        active_scans[scan_id] = False
        socketio.emit("batch_full_scan_complete")

    socketio.start_background_task(run_batch)


@socketio.on("stop_batch_scan")
def handle_stop_batch_scan():
    """Stop any running batch scan."""
    active_scans["batch_full_scan"] = False
    active_scans["batch_nmap_scan"] = False


@socketio.on("live_update")
def handle_live_update(data):
    """Re-ping a list of IPs and emit results for any that changed."""
    ips = data.get("ips", [])
    ping_count = data.get("ping_count", 2)
    if not ips:
        return

    def run_live_pings():
        from concurrent.futures import ThreadPoolExecutor, as_completed

        timeout = app.config["PING_TIMEOUT"]
        total = len(ips)
        done = 0

        with ThreadPoolExecutor(max_workers=min(50, total)) as executor:
            futures = {executor.submit(_ping_host, ip, timeout, ping_count): ip for ip in ips}
            for future in as_completed(futures):
                result = future.result()
                done += 1
                socketio.emit("live_update_result", result)
                socketio.emit("live_update_progress", {
                    "done": done,
                    "total": total,
                    "progress": round((done / total) * 100, 1),
                })

        socketio.emit("live_update_complete")

    socketio.start_background_task(run_live_pings)


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
