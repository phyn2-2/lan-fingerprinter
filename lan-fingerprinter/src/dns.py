"""
src/dns.py — Phase 3: Passive DNS query parser
Extracts domain queries from DNS traffic without sending any packets.
Only processes DNS queries (QR=0), not responses.
"""

from scapy.all import DNS, DNSQR, IP, Ether
from typing import Optional

# DNS query types we care about
QUERY_TYPE_MAP = {
    1:   "A",
    2:   "NS",
    5:   "CNAME",
    12:  "PTR",
    15:  "MX",
    16:  "TXT",
    28:  "AAAA",
    33:  "SRV",
    255: "ANY",
}

# Domains that are noisy and low-signal — skip logging these
NOISE_DOMAINS = {
    "local", "localhost", "localdomain",
    "in-addr.arpa", "ip6.arpa",
}


def parse_dns_query(pkt) -> Optional[dict]:
    """
    Parse a DNS query packet and extract fingerprinting signals.

    Returns a dict with:
        ip          (str)  — source IP of the querying device
        mac         (str)  — source MAC (from Ethernet layer)
        domain      (str)  — queried domain name, lowercased, trailing dot stripped
        query_type  (str)  — query type string e.g. "A", "AAAA", "PTR"

    Returns None if:
        - Not a DNS query (QR=1 means response — skip)
        - No valid DNSQR layer
        - Domain is empty or noise-only
    """
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
        return None

    dns = pkt[DNS]

    # QR=0 → query, QR=1 → response. Only process queries.
    if dns.qr != 0:
        return None

    # Must have at least one question record
    if dns.qdcount < 1 or not dns.qd:
        return None

    # Extract queried domain — Scapy returns bytes with trailing dot
    raw_qname = dns.qd.qname
    if isinstance(raw_qname, bytes):
        domain = raw_qname.decode("utf-8", errors="replace").rstrip(".").lower()
    else:
        domain = str(raw_qname).rstrip(".").lower()

    if not domain:
        return None

    # Skip pure noise domains (PTR reverse lookups, mDNS local, etc.)
    if any(domain == nd or domain.endswith("." + nd) for nd in NOISE_DOMAINS):
        return None

    # Query type
    qtype_int = dns.qd.qtype
    query_type = QUERY_TYPE_MAP.get(qtype_int, str(qtype_int))

    # Source IP
    ip = pkt[IP].src

    # Source MAC from Ethernet layer — best effort
    mac = ""
    if pkt.haslayer(Ether):
        mac = pkt[Ether].src.lower()

    return {
        "ip":         ip,
        "mac":        mac,
        "domain":     domain,
        "query_type": query_type,
    }


def classify_os_from_domain(domain: str) -> Optional[str]:
    """
    Phase 3: Infer OS/platform from queried domain patterns.
    Returns an OS string if a strong signal is found, else None.
    Called from fingerprint.py to supplement TTL + DHCP signals.
    """
    d = domain.lower()

    # Android / Google
    if any(s in d for s in ("gstatic.com", "android", "googleapis.com",
                             "play.google.com", "connectivitycheck.gstatic")):
        return "Android"

    # Apple — iOS / macOS
    if any(s in d for s in ("captive.apple.com", "apple.com", "icloud.com",
                             "mzstatic.com", "appleiphonecell.com")):
        return "Apple (iOS / macOS)"

    # Windows / Microsoft
    if any(s in d for s in ("microsoft.com", "windows.com", "time.windows.com",
                             "windowsupdate.com", "msftncsi.com", "msftconnecttest")):
        return "Windows"

    # Linux desktop (common update/NTP domains)
    if any(s in d for s in ("ubuntu.com", "debian.org", "fedoraproject.org",
                             "archlinux.org", "ntp.ubuntu.com")):
        return "Linux"

    return None
