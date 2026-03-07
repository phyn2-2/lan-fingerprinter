import csv
import requests
from pathlib import Path

OUI_URL = "http://standards-oui.ieee.org/oui/oui.csv"
OUI_FILE = Path("data/oui.csv")

def load_oui_db():
    if not OUI_FILE.exists():
        print("[+] Downloading IEEE OUI database (one-time)...")
        OUI_FILE.parent.mkdir(exist_ok=True)
        r = requests.get(OUI_URL, timeout=10)
        r.raise_for_status()
        OUI_FILE.write_text(r.text)
        print("[+] OUI database ready.")

    db = {}
    with open(OUI_FILE, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            mac_prefix = row['Assignment'].lower().replace('-', ':')
            db[mac_prefix] = row['Organization Name']
        return db
