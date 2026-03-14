"""
src/dhcp.py — Phase 2: Passive DHCP option parser
Extracts fingerprinting signals from DHCP Discover/Request packets.
No packets are sent — purely observational.
"""

from scapy.all import BOOTP, DHCP
from typing import Optional


# DHCP message types we care about (1=Discover, 3=Request)
DHCP_FINGERPRINT_TYPES = {1, 3}


def parse_dhcp_options(pkt) -> Optional[dict]:
    """
    Parse DHCP options from a Scapy packet.

    Returns a dict with keys:
        mac         (str)  — client MAC from BOOTP chaddr field
        ip          (str)  — requested/offered IP (ciaddr or option 50)
        hostname    (str)  — DHCP option 12, or "" if absent
        vendor_class (str) — DHCP option 60, or "" if absent
        param_list  (str)  — DHCP option 55 as comma-separated ints, or ""
        msg_type    (int)  — DHCP message type (1=Discover, 3=Request, etc.)

    Returns None if packet is not a valid DHCP fingerprinting candidate.
    """
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
        return None

    bootp = pkt[BOOTP]
    dhcp_opts = pkt[DHCP].options

    # Parse options into a flat dict for easy access
    options = {}
    for opt in dhcp_opts:
        if isinstance(opt, tuple) and len(opt) >= 2:
            options[opt[0]] = opt[1]

    # Only process Discover (1) and Request (3) — these carry client fingerprints
    msg_type = options.get("message-type", 0)
    if msg_type not in DHCP_FINGERPRINT_TYPES:
        return None

    # MAC from BOOTP layer (chaddr field) — more reliable than Ethernet src
    raw_mac = bootp.chaddr
    if raw_mac:
        mac = ":".join(f"{b:02x}" for b in raw_mac[:6])
    else:
        mac = ""

    # Client IP: ciaddr if already assigned, else fallback to empty
    ip = bootp.ciaddr if bootp.ciaddr and bootp.ciaddr != "0.0.0.0" else ""

    # Option 12 — Hostname (bytes or str depending on Scapy version)
    raw_hostname = options.get("hostname", b"")
    if isinstance(raw_hostname, bytes):
        hostname = raw_hostname.decode("utf-8", errors="replace").strip()
    else:
        hostname = str(raw_hostname).strip()

    # Option 60 — Vendor Class Identifier
    raw_vendor_class = options.get("vendor_class_id", b"")
    if isinstance(raw_vendor_class, bytes):
        vendor_class = raw_vendor_class.decode("utf-8", errors="replace").strip()
    else:
        vendor_class = str(raw_vendor_class).strip()

    # Option 55 — Parameter Request List (list of ints → "1,3,6,15,28")
    param_request = options.get("param_req_list", [])
    if isinstance(param_request, (bytes, bytearray)):
        param_list = ",".join(str(b) for b in param_request)
    elif isinstance(param_request, (list, tuple)):
        param_list = ",".join(str(x) for x in param_request)
    else:
        param_list = ""

    return {
        "mac": mac,
        "ip": ip,
        "hostname": hostname,
        "vendor_class": vendor_class,
        "param_list": param_list,
        "msg_type": msg_type,
    }
