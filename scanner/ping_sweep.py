"""
Ping sweep module — fast parallel ping sweep of a subnet.
"""

import subprocess
import platform
import ipaddress
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def _ping_host(ip: str, timeout: int = 1) -> dict:
    """Ping a single host and return result dict."""
    ip_str = str(ip)
    start = time.perf_counter()

    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"

    try:
        result = subprocess.run(
            ["ping", param, "1", timeout_flag, str(timeout), ip_str],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2,
        )
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        alive = result.returncode == 0

        # Parse response time from ping output
        response_time = None
        if alive:
            output = result.stdout.decode("utf-8", errors="ignore")
            for part in output.split():
                if part.startswith("time=") or part.startswith("time<"):
                    try:
                        response_time = float(part.split("=")[-1].replace("ms", "").replace("<", ""))
                    except ValueError:
                        response_time = elapsed

        # Try reverse DNS
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        return {
            "ip": ip_str,
            "alive": alive,
            "response_time": response_time,
            "hostname": hostname,
            "elapsed": elapsed,
        }

    except subprocess.TimeoutExpired:
        return {
            "ip": ip_str,
            "alive": False,
            "response_time": None,
            "hostname": None,
            "elapsed": None,
        }
    except Exception as e:
        return {
            "ip": ip_str,
            "alive": False,
            "response_time": None,
            "hostname": None,
            "elapsed": None,
            "error": str(e),
        }


def ping_sweep(subnet: str, timeout: int = 1, max_threads: int = 100, callback=None):
    """
    Perform a ping sweep on the given subnet (CIDR notation).
    If callback is provided, call it with each result as it completes.
    Returns list of all results.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid subnet: {subnet} — {e}")

    hosts = list(network.hosts())
    if not hosts:
        hosts = [network.network_address]

    total = len(hosts)
    results = []

    with ThreadPoolExecutor(max_workers=min(max_threads, total)) as executor:
        future_to_ip = {
            executor.submit(_ping_host, str(ip), timeout): str(ip)
            for ip in hosts
        }

        for i, future in enumerate(as_completed(future_to_ip), 1):
            result = future.result()
            result["index"] = i
            result["total"] = total
            result["progress"] = round((i / total) * 100, 1)
            results.append(result)

            if callback:
                callback(result)

    # Sort results by IP address
    results.sort(key=lambda r: ipaddress.ip_address(r["ip"]))
    return results
