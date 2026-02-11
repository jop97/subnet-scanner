"""
Ping sweep module — fast parallel ping sweep of a subnet.
"""

import subprocess
import platform
import ipaddress
import time
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

_IS_WINDOWS = platform.system().lower() == "windows"
_SUBPROCESS_FLAGS = {"creationflags": 0x08000000} if _IS_WINDOWS else {}


def _ttl_os_guess(ttl):
    """Guess OS family from ping TTL value."""
    if ttl is None:
        return None
    ttl = int(ttl)
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device"
    return None


def _ping_host(ip: str, timeout: int = 1, count: int = 1) -> dict:
    """Ping a single host and return result dict."""
    ip_str = str(ip)

    param = "-n" if _IS_WINDOWS else "-c"
    timeout_flag = "-w" if _IS_WINDOWS else "-W"
    # Windows -w expects milliseconds; Linux/Mac -W expects seconds
    timeout_value = str(timeout * 1000) if _IS_WINDOWS else str(timeout)
    ping_count = str(count) if count else "1"

    cmd = ["ping", param, ping_count, timeout_flag, timeout_value, ip_str]

    try:
        start = time.perf_counter()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=(timeout * count) + 4,
            **_SUBPROCESS_FLAGS,
        )
        elapsed = round((time.perf_counter() - start) * 1000, 2)

        alive = result.returncode == 0

        response_time = None
        ttl = None
        if alive:
            output = result.stdout.decode("utf-8", errors="ignore")

            # Parse response times with locale-independent regex.
            # Matches time=1ms, time<1ms, tijd=0.5ms, Zeit<1ms, etc.
            reply_times = re.findall(
                r"[=<]\s*(\d+[.,]?\d*)\s*ms",
                output, re.IGNORECASE
            )
            if reply_times:
                parsed = [float(t.replace(",", ".")) for t in reply_times]
                # Take only the first 'count' values (skip summary stats)
                use = parsed[:count] if len(parsed) > count else parsed
                response_time = round(sum(use) / len(use), 2)
            else:
                response_time = elapsed

            # Parse TTL for OS fingerprinting
            ttl_match = re.search(r"ttl[=]\s*(\d+)", output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))

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
            "ttl": ttl,
            "ttl_os_guess": _ttl_os_guess(ttl),
        }

    except subprocess.TimeoutExpired:
        return {
            "ip": ip_str,
            "alive": False,
            "response_time": None,
            "hostname": None,
            "elapsed": None,
            "ttl": None,
            "ttl_os_guess": None,
        }
    except Exception as e:
        return {
            "ip": ip_str,
            "alive": False,
            "response_time": None,
            "hostname": None,
            "elapsed": None,
            "ttl": None,
            "ttl_os_guess": None,
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
