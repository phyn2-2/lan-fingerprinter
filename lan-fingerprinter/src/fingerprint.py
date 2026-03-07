def get_vendor(mac: str, oui_db: dict) -> str:
    """Lookup vendor from first 3 bytes of MAC (OUI)"""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8].replace(":", "-")      # 00-11-22
    return oui_db.get(prefix, "Unknown")

def guess_os_from_ttl(ttl: int) -> str:
    """Very basic TTL fingerprinting"""
    if ttl == 64:
        return "Linux / Android / macOS"
    elif ttl == 128:
        return "Windows"
    elif ttl == 255:
        return "Cisco / Router / IoT (often)"
    elif 1 <= ttl <= 255:
        return f"Unknown (TTL {ttl})"
    return "Unknown"

