"""
src/fingerprint.py — Device identification logic
Phase 1:   MAC OUI → vendor name
Phase 1.5: TTL → OS guess
Phase 2:   hostname + vendor_class → improved OS + device type
"""

from typing import Optional


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
    Phase 2: DHCP-based OS fingerprinting.
    Returns an OS string if a strong signal is found, else None
    (caller should fall back to TTL-based guess).
    """
    hn = hostname.lower()
    vc = vendor_class.lower()

    # Android
    if hn.startswith("android") or "android" in vc:
        return "Android"

    # Windows — DHCP vendor class is consistently "MSFT 5.0"
    if "msft" in vc or hn.startswith("desktop-") or hn.startswith("win"):
        return "Windows"

    # Apple — iOS/macOS use "dhcpcd" or blank hostname; vendor class signals
    if "apple" in vc or "iphone" in hn or "ipad" in hn or "macbook" in hn:
        return "Apple (iOS / macOS)"

    # Linux embedded / OpenWRT routers
    if "linux" in vc or "openwrt" in vc or "ddwrt" in vc:
        return "Linux (embedded)"

    return None


def guess_type_from_all_signals(
    os_guess: str,
    vendor: str,
    hostname: str,
    vendor_class: str,
) -> str:
    """
    Phase 2: Combined device type inference using TTL OS guess,
    MAC vendor, DHCP hostname, and DHCP vendor class.
    """
    hn = hostname.lower()
    vc = vendor_class.lower()
    os_u = os_guess.upper()
    vendor_u = vendor.upper()

    # --- Router / AP detection ---
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

    # --- Android phone ---
    if hn.startswith("android") or "SM-" in hostname or "android" in vc:
        return "Android Phone"

    # --- Windows PC ---
    if hn.startswith("desktop-") or hn.startswith("win") or "WINDOWS" in os_u or "MSFT" in vc.upper():
        return "Windows PC"

    # --- Apple device ---
    if "iphone" in hn or "ipad" in hn:
        return "iPhone / iPad"
    if "macbook" in hn or "imac" in hn:
        return "Mac"

    # --- Mobile (generic, by vendor) ---
    mobile_vendors = ["SAMSUNG", "XIAOMI", "OPPO", "VIVO", "ONEPLUS",
                      "REALME", "TECNO", "INFINIX"]
    if any(v in vendor_u for v in mobile_vendors):
        return "Mobile"
    if "ANDROID" in os_u:
        return "Mobile"

    # --- PC / Laptop by known NIC vendors ---
    pc_vendors = ["INTEL", "DELL", "HP", "LENOVO", "APPLE", "ACER"]
    if any(v in vendor_u for v in pc_vendors):
        if "WINDOWS" in os_u:
            return "Windows PC"
        if "LINUX" in os_u or "MACOS" in os_u:
            return "Linux / Mac"
        return "PC / Laptop"

    # --- Raspberry Pi / SBC ---
    if "RASPBERRY" in vendor_u:
        return "SBC (Pi)"

    return "Unknown"
