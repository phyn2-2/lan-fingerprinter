import csv
import requests
from pathlib import Path

OUI_FILE = Path("data/oui.csv")

SOURCES = [
    {
        "url": "https://maclookup.app/downloads/csv-database",
        "label": "maclookup.app",
    },
    {
        "url": "https://standards-oui.ieee.org/oui/oui.csv",
        "label": "IEEE",
    },
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
                # Reject HTML responses (bot-detection redirect)
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
    if 'Assignment' in fields:
        return 'ieee'
    if 'MAC Prefix' in fields:
        return 'maclookup'
    return 'unknown'

def load_oui_db():
    if not OUI_FILE.exists():
        _download()

    db = {}
    with open(OUI_FILE, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fmt = _detect_format(reader.fieldnames or [])

        for row in reader:
            if fmt == 'ieee':
                # Assignment: "0050C2" → "00-50-C2"
                raw = row.get('Assignment', '').strip().upper()
                if len(raw) != 6:
                    continue
                prefix = f"{raw[0:2]}-{raw[2:4]}-{raw[4:6]}"
                vendor = row.get('Organization Name', '').strip()

            elif fmt == 'maclookup':
                # MAC Prefix: "00:50:C2" or "00-50-C2" → normalize to "00-50-C2"
                raw = row.get('MAC Prefix', '').strip().upper().replace(':', '-')
                prefix = raw[:8]
                vendor = row.get('Vendor Name', '').strip()

            else:
                continue

            # fingerprint.py lookups use "00-50-C2" (uppercase dashes)
            if prefix and vendor and vendor != 'Unknown':
                db[prefix] = vendor

    return db
