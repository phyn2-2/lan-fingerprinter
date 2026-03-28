"""
src/fingerprint.py — Device identification logic
Phase 1:   MAC OUI → vendor name
Phase 1.5: TTL → OS guess
Phase 2:   hostname + vendor_class → improved OS + device type
Phase 3:   DNS domain patterns → OS confirmation + device type refinement
"""

from typing import Optional
from .dns import classify_os_from_domain            # Phase 3


def get_vendor(mac: str, oui_db: dict) -> str:
    """Lookup vendor from first 3 bytes of MAC (OUI)."""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8].replace(":", "-")      # → "00-1A-2B"
    return oui_db.get(prefix, "Unknown")


def guess_os_from_ttl(ttl: Optional[int]) -> str:
    """
    TTL-based OS fingerprinting from ICMP echo reply IP header.
    On a LAN (1 hop), observed TTL ≈ original TTL set by the OS.
    """
    if ttl is None:
        return "Unknown"
    if ttl == 64:
        return "Linux / Android / macOS (TTL 64)"
    if ttl == 128:
        return "Windows (TTL 128)"
    if ttl == 255:
        return "Router / IoT / Cisco (TTL 255)"
    if 50 <= ttl <= 70:
        return f"Likely Linux-like (TTL {ttl})"
    if 120 <= ttl <= 140:
        return f"Likely Windows-like (TTL {ttl})"
    return f"Unknown (TTL {ttl})"


def guess_os_from_dhcp(hostname: str, vendor_class: str) -> Optional[str]:
    """
    DHCP-based OS fingerprinting (Phase 2).
    Returns an OS string if a strong signal is found, else None.
    """
    hn = hostname.lower()
    vc = vendor_class.lower()

    if hn.startswith("android") or "android" in vc:
        return "Android"
    if "msft" in vc or hn.startswith("desktop-") or hn.startswith("win"):
        return "Windows"
    if "apple" in vc or "iphone" in hn or "ipad" in hn or "macbook" in hn:
        return "Apple (iOS / macOS)"
    if "linux" in vc or "openwrt" in vc or "ddwrt" in vc:
        return "Linux (embedded)"
    return None


def resolve_os_guess(
    ttl: Optional[int],
    hostname: str,
    vendor_class: str,
    last_dns_domain: str,
) -> str:
    """
    Phase 3: Multi-signal OS resolution with priority chain:
      1. DHCP (strongest — device explicitly announces itself)
      2. DNS domain patterns (high confidence for known platforms)
      3. TTL (fallback — indirect, affected by hop count)
    """
    # Priority 1: DHCP
    dhcp_os = guess_os_from_dhcp(hostname, vendor_class)
    if dhcp_os:
        return dhcp_os

    # Priority 2: DNS domain (Phase 3)
    if last_dns_domain:
        dns_os = classify_os_from_domain(last_dns_domain)
        if dns_os:
            return dns_os

    # Priority 3: TTL fallback
    return guess_os_from_ttl(ttl)


def guess_type_from_all_signals(
    os_guess: str,
    vendor: str,
    hostname: str,
    vendor_class: str,
    last_dns_domain: str = "",   # Phase 3
) -> str:
    """
    Combined device type inference using all available signals:
    MAC vendor, TTL OS guess, DHCP hostname + vendor class, DNS domain.
    """
    hn = hostname.lower()
    vc = vendor_class.lower()
    dns = last_dns_domain.lower()
    os_u = os_guess.upper()
    vendor_u = vendor.upper()

    # ── Router / AP ──────────────────────────────────────────────────────────
    router_vendors = [
        "TENDA", "TP-LINK", "HUAWEI", "CISCO", "MIKROTIK",
        "UBIQUITI", "ASUS", "NETGEAR", "DLINK", "ZYXEL", "CYBERTAN",
    ]
    if any(v in vendor_u for v in router_vendors):
        return "Router / AP"
    if "router" in vc or "tplink" in vc or "openwrt" in vc:
        return "Router / AP"
    if "ROUTER" in os_u or "TTL 255" in os_u or "CISCO" in os_u:
        return "Router / IoT"

    # ── Android (DHCP hostname, DNS, or vendor) ───────────────────────────────
    if (hn.startswith("android") or "SM-" in hostname
            or "android" in vc
            or "gstatic.com" in dns
            or "googleapis" in dns):
        return "Android Phone"

    # ── iOS / macOS (DHCP hostname or DNS) ───────────────────────────────────
    if "iphone" in hn or "ipad" in hn:
        return "iPhone / iPad"
    if "macbook" in hn or "imac" in hn:
        return "Mac"
    if "captive.apple" in dns or ("apple.com" in dns and "iphone" not in hn):
        return "Apple Device"

    # ── Windows PC (DHCP hostname, vendor class, or DNS) ─────────────────────
    if (hn.startswith("desktop-") or hn.startswith("win")
            or "MSFT" in vc.upper()
            or "WINDOWS" in os_u
            or "microsoft.com" in dns
            or "windowsupdate" in dns):
        return "Windows PC"

    # ── Linux desktop (DNS signals) ───────────────────────────────────────────
    if any(s in dns for s in ("ubuntu.com", "debian.org", "archlinux.org")):
        return "Linux PC"

    # ── Mobile (generic vendor) ───────────────────────────────────────────────
    mobile_vendors = ["SAMSUNG", "XIAOMI", "OPPO", "VIVO", "ONEPLUS",
                      "REALME", "TECNO", "INFINIX"]
    if any(v in vendor_u for v in mobile_vendors):
        return "Mobile"
    if "ANDROID" in os_u:
        return "Mobile"

    # ── PC / Laptop by NIC vendor ─────────────────────────────────────────────
    pc_vendors = ["INTEL", "DELL", "HP", "LENOVO", "APPLE", "ACER"]
    if any(v in vendor_u for v in pc_vendors):
        if "WINDOWS" in os_u:
            return "Windows PC"
        if "LINUX" in os_u or "MACOS" in os_u:
            return "Linux / Mac"
        return "PC / Laptop"

    # ── Raspberry Pi / SBC ────────────────────────────────────────────────────
    if "RASPBERRY" in vendor_u:
        return "SBC (Pi)"

    return "Unknown"
