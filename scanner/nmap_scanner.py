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


def _new_result_dict(ip: str) -> dict:
    """Return a blank result template for nmap scan output."""
    return {
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


def _parse_scan_result(scanner, ip: str, *, error: str = None,
                       tried_fallback: bool = False) -> dict:
    """Extract host info from a populated PortScanner object."""
    result = _new_result_dict(ip)
    if error:
        result["error"] = error

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


def scan_host(ip: str, arguments: str = "-Pn -sV -sC -O --top-ports 100", timeout: int = 60) -> dict:
    """
    Run an nmap scan on a single host and return rich information.
    Falls back to non-privileged arguments if OS detection fails.
    On Windows without admin, --unprivileged is added automatically
    to prevent UAC / Npcap admin helper popups.
    """
    if platform.system() == "Windows" and not _is_admin() and "--unprivileged" not in arguments:
        arguments += " --unprivileged"

    scanner = nmap.PortScanner()
    tried_fallback = False
    error_msg_out = None

    try:
        scanner.scan(hosts=ip, arguments=arguments, timeout=timeout)
    except nmap.PortScannerError as e:
        error_msg = str(e)
        if ("-O" in arguments or "-A" in arguments) and (
            "requires root" in error_msg.lower()
            or "privilege" in error_msg.lower()
            or "raw socket" in error_msg.lower()
        ):
            tried_fallback = True
            fallback_args = arguments.replace("-O", "").replace("-A", "").strip()
            fallback_args = " ".join(fallback_args.split())
            try:
                scanner.scan(hosts=ip, arguments=fallback_args, timeout=timeout)
                error_msg_out = "OS detection requires admin privileges — skipped."
            except Exception as e2:
                return {**_new_result_dict(ip), "error": f"Nmap error: {e2}"}
        else:
            return {**_new_result_dict(ip), "error": f"Nmap error: {error_msg}"}
    except Exception as e:
        return {**_new_result_dict(ip), "error": f"Scan error: {e}"}

    return _parse_scan_result(scanner, ip, error=error_msg_out,
                              tried_fallback=tried_fallback)


def quick_scan(ip: str, timeout: int = 30) -> dict:
    """Quick scan — top 20 ports, service version only."""
    return scan_host(ip, arguments="-Pn -sV --top-ports 20 -T4", timeout=timeout)


def full_scan(ip: str, timeout: int = 180) -> dict:
    """Full scan — common ports with OS detection and scripts (if admin)."""
    if _is_admin():
        return scan_host(ip, arguments="-Pn -sV -sC -O -A --top-ports 1000", timeout=timeout)
    else:
        # Without admin, skip -O and -A which need raw sockets
        # --unprivileged is added automatically by scan_host() on Windows
        return scan_host(ip, arguments="-Pn -sV -sC --top-ports 1000", timeout=timeout)


def full_scan_with_progress(ip: str, progress_callback=None,
                            timeout: int = 150,
                            top_ports: int = 2500,
                            host_timeout: int = 180) -> dict:
    """
    Full scan with real-time progress reporting.

    Runs nmap directly as a subprocess with ``--stats-every 2s`` so
    the caller can display scan progress.  *progress_callback(pct)*
    is called with the completion percentage (0-100) whenever nmap
    reports it.

    Args:
        ip: Target IP address
        progress_callback: Function called with progress percentage (0-100)
        timeout: Overall timeout for the subprocess in seconds
        top_ports: Number of top ports to scan (default 2500)
        host_timeout: Nmap --host-timeout value in seconds (default 180)
    """
    import subprocess
    import re
    import shutil
    import threading
    import tempfile
    import os

    # Build arguments
    # -Pn: skip host discovery — we already know the host is up from ping sweep
    host_timeout_s = f"--host-timeout {host_timeout}s"
    if _is_admin():
        arguments = f"-Pn -sV -sC -O -A --top-ports {top_ports} -T4 {host_timeout_s}"
    else:
        arguments = f"-Pn -sV -sC --top-ports {top_ports} -T4 {host_timeout_s}"

    if platform.system() == "Windows" and not _is_admin():
        arguments += " --unprivileged"

    # Locate nmap binary
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return {**_new_result_dict(ip), "error": "nmap not found on PATH"}

    # Write XML to a temp file so stdout is free for progress lines
    tmp_fd, tmp_xml = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
    os.close(tmp_fd)

    cmd = [nmap_bin] + arguments.split() + [
        "--stats-every", "2s", "-oX", tmp_xml, ip,
    ]

    # Hide console window on Windows
    kw = {}
    if platform.system() == "Windows":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw,
        )
    except Exception as e:
        return {**_new_result_dict(ip), "error": f"Failed to start nmap: {e}"}

    # Background thread reads stdout for nmap progress lines
    # (nmap writes interactive progress to stdout, not stderr)
    pct_re = re.compile(r"About (\d+\.?\d*)% done")

    def _read_progress():
        try:
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace")
                m = pct_re.search(line)
                if m and progress_callback:
                    progress_callback(float(m.group(1)))
        except Exception:
            pass
        finally:
            # Ensure stdout is closed so proc.wait() can return
            try:
                proc.stdout.close()
            except Exception:
                pass

    t = threading.Thread(target=_read_progress, daemon=True)
    t.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass  # Process is truly stuck, move on

    t.join(timeout=5)

    # Read XML from temp file (may contain partial results on timeout)
    try:
        with open(tmp_xml, "r", encoding="utf-8", errors="replace") as f:
            xml = f.read()
    except Exception as e:
        return {**_new_result_dict(ip), "error": f"Failed to read nmap XML: {e}"}
    finally:
        try:
            os.unlink(tmp_xml)
        except OSError:
            pass

    if not xml or len(xml.strip()) < 50:
        msg = "Nmap scan timed out — no results" if timed_out else "Nmap produced no output"
        return {**_new_result_dict(ip), "error": msg}

    scanner = nmap.PortScanner()
    try:
        scanner.analyse_nmap_xml_scan(nmap_xml_output=xml)
    except Exception as e:
        return {**_new_result_dict(ip), "error": f"Nmap XML parse error: {e}"}

    result = _parse_scan_result(scanner, ip)

    if timed_out and not result.get("error"):
        result["error"] = "Scan timed out — results may be incomplete"

    return result
