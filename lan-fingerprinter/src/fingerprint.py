from typing import Optional

def get_vendor(mac: str, oui_db: dict) -> str:
    """Lookup vendor from first 3 bytes of MAC (OUI)"""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8].replace(":", "-")      # 00-11-22
    return oui_db.get(prefix, "Unknown")

def guess_os_from_ttl(ttl: Optional[int]) -> str:
    """
    Phase 1.5: Improved TTL-based OS fingerprinting.
    TTL is read from the IP header of ICMP echo replies.
    On a LAN (1 hop), observed TTL = original TTL set by OS.
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

def guess_type_from_os_and_vendor(os_guess: str, vendor: str) -> str:
    """
    Phase 1.5: Infer device type from OS guess + vendor name.
    Used to populate the 'Type' column ith more useful data.
    """
    vendor_upper = vendor.upper()
    os_upper = os_guess.upper()

    # Router/gateway detection
    router_vendors = [
                    "TENDA", "TP-LINK", "HUAWEI", "CISCO", "MIKROTIK",
                    "UBIQUITI", "ASUS", "NETGEAR", "DLINK", "ZYXEL", "CYBERTAN"]
    if any(v in vendor_upper for v in router_vendors):
        return "Router / AP"
    if "ROUTER" in os_upper or "CISCO" in os_upper or "TTL 255" in os_upper:
        return "Router / IoT"

    # Mobile/Android detection
    mobile_vendors = ["SAMSUNG", "XIAOMI", "OPPO", "VIVO", "ONEPLUS",
                      "HUAWEI", "REALME", "TECNO", "INFINIX"]
    if any(v in vendor_upper for v in mobile_vendors):
        return "Mobile"
    if "ANDROID" in os_upper:
        return "Mobile"

    # Desktop/laptop detection
    pc_vendors = ["INTEL", "DEL", "HP", "LENOVO", "APPLE", "ACER","ASUS"]
    if any(v in vendor_upper for v in pc_vendors):
        if "WINDOWS" in os_upper:
            return "Windows PC"
        if "LINUX" in os_upper or "MACOS" in os_upper:
            return "Linux / Mac"
        return "PC / Laptop"

    # Raspberry Pi / SBC
    if "RASPBERRY" in vendor_upper:
        return "SBC (Pi)"

    return "Unknown"


