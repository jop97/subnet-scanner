"""
Subnet Scanner — Flask Application
A modern network scanning web application.
"""

import ipaddress
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from config import Config
from scanner.ping_sweep import ping_sweep
from scanner.nmap_scanner import scan_host, quick_scan
from scanner.host_info import get_full_host_info

app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

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

    active_scans[scan_id] = True
    scan_results[scan_id] = []

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
                timeout=app.config["PING_TIMEOUT"],
                max_threads=app.config["MAX_THREADS"],
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
    scan_type = data.get("scan_type", "quick")

    if not ip:
        emit("host_detail_error", {"error": "No IP provided"})
        return

    emit("host_detail_scanning", {"ip": ip})

    def run_detail_scan():
        try:
            # Get host info
            host_info = get_full_host_info(ip)

            # Run nmap
            if scan_type == "quick":
                nmap_result = quick_scan(ip)
            else:
                nmap_result = scan_host(ip)

            combined = {**host_info, **nmap_result}
            socketio.emit("host_detail_result", combined)

        except Exception as e:
            socketio.emit("host_detail_error", {"error": str(e), "ip": ip})

    socketio.start_background_task(run_detail_scan)


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
