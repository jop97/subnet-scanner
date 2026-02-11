"""
Nmap scanner module — detailed port/service scanning via python-nmap.
"""

import platform
import nmap


def _is_admin() -> bool:
    """Check if the current process has admin/root privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            import os
            return os.geteuid() == 0
    except Exception:
        return False


def scan_host(ip: str, arguments: str = "-sV -sC -O --top-ports 100", timeout: int = 60) -> dict:
    """
    Run an nmap scan on a single host and return rich information.
    Falls back to non-privileged arguments if OS detection fails.
    On Windows without admin, --unprivileged is added automatically
    to prevent UAC / Npcap admin helper popups.
    """
    # On Windows without admin, force unprivileged mode (connect scan)
    # to avoid UAC / Npcap admin helper popups
    if platform.system() == "Windows" and not _is_admin() and "--unprivileged" not in arguments:
        arguments += " --unprivileged"

    scanner = nmap.PortScanner()
    result = {
        "ip": ip,
        "scan_complete": False,
        "hostname": None,
        "hostnames": [],
        "state": "down",
        "os_matches": [],
        "open_ports": [],
        "services": [],
        "mac_address": None,
        "vendor": None,
        "uptime": None,
        "tcp_sequence": None,
        "scripts": {},
        "raw": None,
        "error": None,
    }

    # If not admin and arguments contain OS detection, try with it first
    # and fall back without it on failure
    tried_fallback = False

    try:
        scanner.scan(hosts=ip, arguments=arguments, timeout=timeout)
    except nmap.PortScannerError as e:
        error_msg = str(e)
        # OS detection requires privileges — retry without -O and -A
        if ("-O" in arguments or "-A" in arguments) and ("requires root" in error_msg.lower() or "privilege" in error_msg.lower() or "raw socket" in error_msg.lower()):
            tried_fallback = True
            fallback_args = arguments.replace("-O", "").replace("-A", "").strip()
            fallback_args = " ".join(fallback_args.split())  # clean up double spaces
            try:
                scanner.scan(hosts=ip, arguments=fallback_args, timeout=timeout)
                result["error"] = "OS detection requires admin privileges — skipped."
            except Exception as e2:
                result["error"] = f"Nmap error: {str(e2)}"
                return result
        else:
            result["error"] = f"Nmap error: {error_msg}"
            return result
    except Exception as e:
        result["error"] = f"Scan error: {str(e)}"
        return result

    try:
        if ip not in scanner.all_hosts():
            result["error"] = "Host not found in scan results"
            return result

        host_data = scanner[ip]
        result["state"] = host_data.state()

        # Hostnames
        if "hostnames" in host_data:
            result["hostnames"] = host_data["hostnames"]
            for h in host_data["hostnames"]:
                if h.get("name"):
                    result["hostname"] = h["name"]
                    break

        # OS detection
        if "osmatch" in host_data:
            for os_match in host_data["osmatch"]:
                result["os_matches"].append({
                    "name": os_match.get("name", "Unknown"),
                    "accuracy": os_match.get("accuracy", "0"),
                    "os_classes": os_match.get("osclass", []),
                })

        # MAC address
        if "addresses" in host_data:
            if "mac" in host_data["addresses"]:
                result["mac_address"] = host_data["addresses"]["mac"]

        # Vendor
        if "vendor" in host_data:
            for mac, vendor_name in host_data["vendor"].items():
                result["vendor"] = vendor_name
                break

        # Uptime
        if "uptime" in host_data:
            result["uptime"] = host_data["uptime"]

        # TCP sequence
        if "tcpsequence" in host_data:
            result["tcp_sequence"] = host_data["tcpsequence"]

        # Ports & services
        for proto in host_data.all_protocols():
            ports = sorted(host_data[proto].keys())
            for port in ports:
                port_data = host_data[proto][port]
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "state": port_data.get("state", "unknown"),
                    "service": port_data.get("name", "unknown"),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "cpe": port_data.get("cpe", ""),
                    "scripts": {},
                }

                # NSE scripts output
                if "script" in port_data:
                    port_info["scripts"] = port_data["script"]

                if port_data.get("state") == "open":
                    result["open_ports"].append(port)

                result["services"].append(port_info)

        # Host scripts
        if "hostscript" in host_data:
            for script in host_data["hostscript"]:
                result["scripts"][script.get("id", "unknown")] = script.get("output", "")

        result["scan_complete"] = not tried_fallback or bool(result["os_matches"])
        result["raw"] = scanner.csv()

    except Exception as e:
        result["error"] = f"Parse error: {str(e)}"

    return result


def quick_scan(ip: str, timeout: int = 30) -> dict:
    """Quick scan — top 20 ports, service version only."""
    return scan_host(ip, arguments="-sV --top-ports 20 -T4", timeout=timeout)


def full_scan(ip: str, timeout: int = 180) -> dict:
    """Full scan — common ports with OS detection and scripts (if admin)."""
    if _is_admin():
        return scan_host(ip, arguments="-sV -sC -O -A --top-ports 1000", timeout=timeout)
    else:
        # Without admin, skip -O and -A which need raw sockets
        # --unprivileged is added automatically by scan_host() on Windows
        return scan_host(ip, arguments="-sV -sC --top-ports 1000", timeout=timeout)
