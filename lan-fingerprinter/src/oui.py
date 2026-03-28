"""
src/oui.py — OUI vendor lookup + MAC utility functions
Phase 3.5 adds: is_randomized_mac(), seed_from_arp_cache()
"""

import csv
import requests
from pathlib import Path

OUI_FILE = Path("data/oui.csv")

SOURCES = [
    {"url": "https://maclookup.app/downloads/csv-database", "label": "maclookup.app"},
    {"url": "https://standards-oui.ieee.org/oui/oui.csv",   "label": "IEEE"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
}


def _download():
    OUI_FILE.parent.mkdir(exist_ok=True)
    for source in SOURCES:
        print(f"[+] Trying {source['label']}...")
        try:
            with requests.get(source["url"], headers=HEADERS, timeout=90, stream=True) as r:
                r.raise_for_status()
                content = b""
                for chunk in r.iter_content(chunk_size=8192):
                    content += chunk
                if content.lstrip().startswith(b"<!"):
                    print(f"[-] {source['label']} returned HTML — skipping.")
                    continue
                OUI_FILE.write_bytes(content)
                print(f"[+] Downloaded from {source['label']}.")
                return
        except Exception as e:
            print(f"[-] {source['label']} failed: {e}")
    raise RuntimeError(
        "All OUI sources failed.\n"
        "Manual fix: download https://standards-oui.ieee.org/oui/oui.csv\n"
        "and save as data/oui.csv"
    )


def _detect_format(fieldnames):
    """Return 'ieee' or 'maclookup' based on CSV headers."""
    fields = [f.strip() for f in fieldnames]
    if "Assignment" in fields:
        return "ieee"
    if "MAC Prefix" in fields:
        return "maclookup"
    return "unknown"


def load_oui_db() -> dict:
    if not OUI_FILE.exists():
        _download()

    db = {}
    with open(OUI_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fmt = _detect_format(reader.fieldnames or [])

        for row in reader:
            if fmt == "ieee":
                # Assignment: "0050C2" → "00-50-C2"
                raw = row.get("Assignment", "").strip().upper()
                if len(raw) != 6:
                    continue
                prefix = f"{raw[0:2]}-{raw[2:4]}-{raw[4:6]}"
                vendor = row.get("Organization Name", "").strip()

            elif fmt == "maclookup":
                # MAC Prefix: "00:50:C2" or "00-50-C2" → "00-50-C2"
                raw = row.get("MAC Prefix", "").strip().upper().replace(":", "-")
                prefix = raw[:8]
                vendor = row.get("Vendor Name", "").strip()

            else:
                continue

            # fingerprint.py lookups use "00-50-C2" (uppercase dashes)
            if prefix and vendor and vendor != "Unknown":
                db[prefix] = vendor

    return db


def get_vendor(mac: str, oui_db: dict) -> str:
    """Lookup vendor from first 3 bytes of MAC (OUI)."""
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8].replace(":", "-")      # → "00-1A-2B"
    return oui_db.get(prefix, "Unknown")


def is_randomized_mac(mac: str) -> bool:
    """
    Phase 3.5: Detect locally administered (randomized) MAC addresses.

    The IEEE defines bit 1 (LSB+1) of the first octet as the
    Locally Administered bit. When set, the MAC was not assigned by
    the manufacturer — it's software-generated (randomized).

    Modern Android (10+) and iOS (14+) randomize MACs per network,
    so OUI lookup will always return Unknown for these. Detecting this
    lets us show "[rand] Randomized" instead of a misleading "Unknown".

    Examples:
        "1a:0a:04:7d:a3:95" → first byte 0x1a = 0001 1010 → bit1=1 → True
        "04:95:e6:24:b0:a0" → first byte 0x04 = 0000 0100 → bit1=0 → False
    """
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except (ValueError, IndexError):
        return False


def seed_from_arp_cache(db, oui_db: dict) -> int:
    """
    Phase 3.5: Pre-populate the device DB from the kernel ARP cache
    (/proc/net/arp) without sending any packets — purely passive.

    Returns the number of devices seeded.
    Called once at startup before the sniffer thread starts.
    """
    seeded = 0
    try:
        with open("/proc/net/arp") as f:
            lines = f.readlines()[1:]   # skip header row
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip  = parts[0]
            mac = parts[3].lower()
            if mac == "00:00:00:00:00:00":
                continue    # incomplete ARP entry — kernel hasn't resolved it yet
            if is_randomized_mac(mac):
                vendor = "[rand] Randomized"
            else:
                vendor = get_vendor(mac, oui_db)
            db.update_or_insert_device(ip, mac, vendor)
            seeded += 1
    except Exception as e:
        print(f"[!] Could not seed ARP cache: {e}")
    return seeded
