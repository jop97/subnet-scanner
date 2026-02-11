"""
Host information module — gathers comprehensive data about a host.
"""

import socket
import subprocess

import dns.resolver
import dns.reversename


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
    """Try to get NetBIOS information (Linux only via nmblookup)."""
    info = {"netbios_name": None, "workgroup": None}

    try:
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
    """Get basic WHOIS information."""
    info = {"whois": None}

    try:
        result = subprocess.run(
            ["whois", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if result.returncode == 0:
            info["whois"] = result.stdout.decode("utf-8", errors="ignore")[:2000]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    return info


def get_arp_info(ip: str) -> dict:
    """Get ARP table entry for the IP."""
    info = {"mac_from_arp": None}

    try:
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
    return info
