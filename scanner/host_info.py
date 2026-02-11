"""
Host information module — gathers comprehensive data about a host.
"""

import socket
import subprocess
import platform
import re

import dns.resolver
import dns.reversename

_IS_WINDOWS = platform.system().lower() == "windows"
_SUBPROCESS_FLAGS = {"creationflags": 0x08000000} if _IS_WINDOWS else {}


def get_dns_info(ip: str) -> dict:
    """Get DNS information for an IP address."""
    info = {
        "reverse_dns": None,
        "dns_names": [],
        "ptr_records": [],
    }

    # Reverse DNS lookup
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        info["reverse_dns"] = hostname
        info["dns_names"] = [hostname] + list(aliases)
    except (socket.herror, socket.gaierror, OSError):
        pass

    # PTR record lookup
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        info["ptr_records"] = [str(rdata) for rdata in answers]
    except Exception:
        pass

    return info


def get_netbios_info(ip: str) -> dict:
    """Try to get NetBIOS information via nmblookup or nbtstat."""
    info = {"netbios_name": None, "workgroup": None}

    try:
        if _IS_WINDOWS:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                **_SUBPROCESS_FLAGS,
            )
            if result.returncode == 0:
                output = result.stdout.decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    line = line.strip()
                    if "<00>" in line and "GROUP" not in line.upper():
                        info["netbios_name"] = line.split()[0]
                    elif "<00>" in line and "GROUP" in line.upper():
                        info["workgroup"] = line.split()[0]
        else:
            result = subprocess.run(
                ["nmblookup", "-A", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    line = line.strip()
                    if "<00>" in line and "GROUP" not in line:
                        info["netbios_name"] = line.split()[0]
                    elif "<00>" in line and "GROUP" in line:
                        info["workgroup"] = line.split()[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    return info


def get_whois_info(ip: str) -> dict:
    """Get basic WHOIS information (cross-platform)."""
    info = {"whois": None}

    try:
        cmd = ["whois", ip]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            **_SUBPROCESS_FLAGS,
        )
        if result.returncode == 0:
            info["whois"] = result.stdout.decode("utf-8", errors="ignore")[:2000]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    return info


def get_arp_info(ip: str) -> dict:
    """Get ARP table entry for the IP (cross-platform)."""
    info = {"mac_from_arp": None}

    try:
        if _IS_WINDOWS:
            result = subprocess.run(
                ["arp", "-a", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                **_SUBPROCESS_FLAGS,
            )
            if result.returncode == 0:
                output = result.stdout.decode("utf-8", errors="ignore")
                mac_match = re.search(
                    r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]"
                    r"[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                    output,
                )
                if mac_match:
                    mac = mac_match.group(1).replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        info["mac_from_arp"] = mac
        else:
            result = subprocess.run(
                ["arp", "-n", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.decode("utf-8", errors="ignore")
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == ip:
                        mac = parts[2]
                        if mac != "(incomplete)":
                            info["mac_from_arp"] = mac
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    return info


def get_full_host_info(ip: str) -> dict:
    """Gather all available information about a host."""
    info = {"ip": ip}
    info.update(get_dns_info(ip))
    info.update(get_netbios_info(ip))
    info.update(get_arp_info(ip))
    info.update(get_whois_info(ip))
    return info
