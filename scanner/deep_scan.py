"""
Deep scanning module - additional host probes beyond Nmap.

All probes can be individually toggled via the probe_* parameters
in deep_scan_host(). Settings are passed from the client-side
Settings modal through the WebSocket batch_full_scan event.

Capabilities:
  - MAC Vendor lookup (OUI database via mac-vendor-lookup)
  - SSDP / UPnP discovery (raw multicast, finds smart devices)
  - Full ARP table scan (cross-platform, reads all known MACs)
  - HTTP / HTTPS probing (server headers, page title, fingerprinting)
  - SSL / TLS certificate analysis (subject, issuer, validity, SANs)
  - TCP banner grabbing (SSH, FTP, SMTP, MySQL, etc.)
  - Cross-platform ARP-based MAC resolution
"""

import socket
import ssl
import re
import platform
import subprocess
import tempfile
import os

# Optional: requests for HTTP probing
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Optional: mac-vendor-lookup for OUI -> vendor mapping
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    HAS_MAC_VENDOR = True
except ImportError:
    _mac_lookup = None
    HAS_MAC_VENDOR = False

_IS_WINDOWS = platform.system().lower() == "windows"
_SUBPROCESS_FLAGS = {"creationflags": 0x08000000} if _IS_WINDOWS else {}


# -- MAC Vendor Lookup -------------------------------------------------------

def get_mac_vendor(mac):
    """Look up the manufacturer/vendor for a MAC address via the OUI database."""
    if not HAS_MAC_VENDOR or not mac:
        return None
    try:
        return _mac_lookup.lookup(mac)
    except Exception:
        return None


# -- SSDP / UPnP Discovery ---------------------------------------------------

def ssdp_discover(timeout=4):
    """
    Discover UPnP/SSDP devices on the local network via multicast M-SEARCH.

    Returns:
        dict: {ip: {"server": str, "services": [str], "location": str}}
    """
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900

    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    devices = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                response = data.decode("utf-8", errors="ignore")

                # Parse response headers
                parsed = {}
                for line in response.split("\r\n"):
                    if ":" in line:
                        key, _, value = line.partition(":")
                        k = key.strip().upper()
                        v = value.strip()
                        if k in ("SERVER", "ST", "LOCATION", "USN"):
                            parsed[k.lower()] = v

                if parsed:
                    if ip not in devices:
                        devices[ip] = {
                            "server": None,
                            "location": None,
                            "services": [],
                        }
                    if parsed.get("st"):
                        devices[ip]["services"].append(parsed["st"])
                    if parsed.get("location") and not devices[ip].get("location"):
                        devices[ip]["location"] = parsed["location"]
                    if parsed.get("server"):
                        devices[ip]["server"] = parsed["server"]
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Deduplicate services
    for ip in devices:
        devices[ip]["services"] = sorted(set(devices[ip].get("services", [])))

    return devices


# -- Full ARP Table -----------------------------------------------------------

def get_arp_table_full():
    """
    Read the entire system ARP table.

    Returns:
        dict: {ip: mac} for all entries in the ARP table.
    """
    table = {}

    try:
        result = subprocess.run(
            ["arp", "-a"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            **_SUBPROCESS_FLAGS,
        )

        if result.returncode == 0:
            output = result.stdout.decode("utf-8", errors="ignore")
            ip_mac_re = re.compile(
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*?"
                r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]"
                r"[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})"
            )
            for match in ip_mac_re.finditer(output):
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    table[ip] = mac
    except Exception:
        pass

    return table


# -- Cross-Platform ARP MAC (per IP) -----------------------------------------

def get_arp_mac(ip):
    """Cross-platform ARP lookup to get MAC address for a single IP."""
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
                mac_re = re.compile(
                    r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]"
                    r"[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})"
                )
                match = mac_re.search(output)
                if match:
                    mac = match.group(1).replace("-", ":").upper()
                    if mac != "FF:FF:FF:FF:FF:FF":
                        return mac
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
                        mac = parts[2].upper()
                        if mac != "(INCOMPLETE)":
                            return mac
    except Exception:
        pass

    return None


# -- TTL OS Guess -------------------------------------------------------------

def get_ttl_os_guess(ttl):
    """Guess OS family based on TTL value."""
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


# -- HTTP Probing -------------------------------------------------------------

def get_http_info(ip, port=80, timeout=5):
    """Probe HTTP/HTTPS and return server info, headers, page title."""
    info = {
        "server": None,
        "powered_by": None,
        "title": None,
        "status_code": None,
        "redirect": None,
        "content_type": None,
        "headers": {},
    }

    if not HAS_REQUESTS:
        return info

    try:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}"
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "SubnetScanner/1.0"},
        )
        info["status_code"] = resp.status_code
        info["server"] = resp.headers.get("Server")
        info["powered_by"] = resp.headers.get("X-Powered-By")
        info["content_type"] = resp.headers.get("Content-Type", "")[:100]

        # Extract page title
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>",
            resp.text[:5000],
            re.IGNORECASE | re.DOTALL,
        )
        if title_match:
            info["title"] = title_match.group(1).strip()[:200]

        # Redirect chain
        if resp.history:
            info["redirect"] = resp.url

        # Interesting security / fingerprint headers
        interesting = [
            "Server", "X-Powered-By", "X-Frame-Options", "Content-Type",
            "X-AspNet-Version", "X-Generator", "X-Content-Type-Options",
            "Strict-Transport-Security", "Content-Security-Policy",
        ]
        info["headers"] = {
            k: v for k, v in resp.headers.items() if k in interesting
        }
    except Exception:
        pass

    return info


# -- SSL / TLS Certificate ---------------------------------------------------

def _parse_pem_cert(pem_string):
    """Parse a PEM certificate string into a dict via ssl internals."""
    try:
        fd, cert_file = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(pem_string)
            return ssl._ssl._test_decode_cert(cert_file)
        finally:
            os.unlink(cert_file)
    except Exception:
        return None


def get_ssl_cert_info(ip, port=443, timeout=5):
    """Get SSL/TLS certificate details."""
    info = {
        "ssl_subject": None,
        "ssl_issuer": None,
        "ssl_not_before": None,
        "ssl_not_after": None,
        "ssl_san": [],
        "ssl_version": None,
        "ssl_cipher": None,
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                info["ssl_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    info["ssl_cipher"] = f"{cipher[0]} ({cipher[2]}-bit)"

                # Get DER cert and parse
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    pem = ssl.DER_cert_to_PEM_cert(der_cert)
                    cert_dict = _parse_pem_cert(pem)
                    if cert_dict:
                        # Subject
                        subj = cert_dict.get("subject", ())
                        if subj:
                            subj_dict = {}
                            for rdn in subj:
                                for attr, val in rdn:
                                    subj_dict[attr] = val
                            info["ssl_subject"] = subj_dict.get(
                                "commonName", str(subj_dict)
                            )

                        # Issuer
                        iss = cert_dict.get("issuer", ())
                        if iss:
                            iss_dict = {}
                            for rdn in iss:
                                for attr, val in rdn:
                                    iss_dict[attr] = val
                            info["ssl_issuer"] = iss_dict.get(
                                "organizationName",
                                iss_dict.get("commonName", str(iss_dict)),
                            )

                        info["ssl_not_before"] = cert_dict.get("notBefore")
                        info["ssl_not_after"] = cert_dict.get("notAfter")

                        san = cert_dict.get("subjectAltName", ())
                        info["ssl_san"] = [
                            val for typ, val in san
                            if typ in ("DNS", "IP Address")
                        ]
    except Exception:
        pass

    return info


# -- TCP Banner Grabbing ------------------------------------------------------

_BANNER_PORTS = {
    21, 22, 25, 80, 110, 143, 465, 587, 993, 995,
    2222, 3306, 3389, 5432, 5900, 6379, 8080, 8000, 8888, 9090,
}


def get_tcp_banner(ip, port, timeout=3):
    """Connect to a TCP port and grab the service banner."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # Some services need a prompt
            if port in (80, 8080, 8000, 8888):
                sock.sendall(
                    b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                )
            elif port == 443:
                return None  # SSL handled separately

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:500] if banner else None
    except Exception:
        return None


def get_tcp_banners(ip, ports, timeout=3):
    """Grab banners from a list of open ports."""
    banners = {}
    check_ports = [p for p in ports if p in _BANNER_PORTS]

    for port in check_ports[:10]:  # Max 10 ports
        banner = get_tcp_banner(ip, port, timeout)
        if banner:
            banners[str(port)] = banner

    return banners


# -- Deep Scan Aggregator -----------------------------------------------------

def deep_scan_host(ip, open_ports=None, timeout=5, ssdp_info=None, arp_mac=None,
                   probe_http=True, probe_ssl=True, probe_banners=True,
                   probe_mac_vendor=True):
    """
    Run all deep scan probes on a single host.

    Args:
        ip:              Target IP address
        open_ports:      List of known open ports from nmap
        timeout:         Timeout per probe in seconds
        ssdp_info:       Pre-gathered SSDP data for this IP (from ssdp_discover)
        arp_mac:         Pre-gathered MAC from ARP table scan
        probe_http:      Enable HTTP/HTTPS probing
        probe_ssl:       Enable SSL/TLS certificate analysis
        probe_banners:   Enable TCP banner grabbing
        probe_mac_vendor: Enable MAC vendor (OUI) lookup

    Returns:
        dict with all gathered information
    """
    result = {"ip": ip}

    if open_ports is None:
        open_ports = []

    # -- MAC / ARP lookup
    mac = arp_mac or get_arp_mac(ip)
    if mac:
        result["mac_from_arp"] = mac

        # Vendor lookup via OUI database
        if probe_mac_vendor:
            vendor = get_mac_vendor(mac)
            if vendor:
                result["mac_vendor"] = vendor

    # -- SSDP / UPnP info
    if ssdp_info:
        result["ssdp_info"] = ssdp_info

    # -- HTTP probe (only on ports known to be open)
    if probe_http:
        http_ports = [p for p in [80, 8080, 8000, 8888] if p in open_ports]
        for port in http_ports:
            info = get_http_info(ip, port, timeout)
            if info.get("status_code"):
                info["port"] = port
                result["http_info"] = info
                break

        # -- HTTPS probe (only on ports known to be open)
        https_ports = [p for p in [443, 8443] if p in open_ports]
        for port in https_ports:
            info = get_http_info(ip, port, timeout)
            if info.get("status_code"):
                info["port"] = port
                if "http_info" not in result:
                    result["http_info"] = info
                result["https_info"] = info
                break

    # -- SSL certificate (only on ports known to be open)
    if probe_ssl:
        ssl_ports = [p for p in [443, 8443] if p in open_ports]
        for port in ssl_ports:
            ssl_info = get_ssl_cert_info(ip, port, timeout)
            if ssl_info.get("ssl_version"):
                ssl_info["port"] = port
                result["ssl_info"] = ssl_info
                break

    # -- TCP banners from known open ports
    if probe_banners and open_ports:
        banners = get_tcp_banners(ip, open_ports, timeout=min(timeout, 3))
        if banners:
            result["banners"] = banners

    return result
