# lan-fingerprinter

A passive LAN device fingerprinter that identifies, tracks, and classifies devices on your local network using ARP, ICMP TTL, DHCP, and DNS — without sending a single packet.

---

## Features

### Phase 1 — Passive ARP Discovery
- Sniffs ARP traffic on any interface (WiFi or Ethernet)
- Extracts IP address, MAC address per device
- Resolves MAC OUI prefix → vendor name via IEEE database (auto-downloaded)
- Persists all discovered devices to SQLite with `first_seen` / `last_seen` timestamps
- Live terminal table powered by [Rich](https://github.com/Textualize/rich)

### Phase 1.5 — ICMP TTL OS Fingerprinting
- Passively captures ICMP echo replies (type 0)
- Extracts TTL from IP header to infer OS family:

  | TTL | OS Guess |
  |-----|----------|
  | 64  | Linux / Android / macOS |
  | 128 | Windows |
  | 255 | Router / Cisco / IoT |
  | 50–70 | Likely Linux-like |
  | 120–140 | Likely Windows-like |

### Phase 2 — Passive DHCP Fingerprinting
- Sniffs DHCP Discover/Request packets (UDP 68→67)
- Extracts:
  - **Option 12** — Hostname (e.g. `TECNO-SPARK-8C`, `Iphone-15-pro-max`)
  - **Option 60** — Vendor Class Identifier (e.g. `MSFT 5.0`, `android-dhcp-13`)
  - **Option 55** — Parameter Request List (fingerprint string)
- Improves OS and device type classification significantly

### Phase 3 — Passive DNS Tracking
- Sniffs DNS queries (UDP port 53, QR=0 only)
- Extracts queried domain name and query type per device
- Uses domain patterns for OS inference:
  - `gstatic.com`, `googleapis` → Android
  - `captive.apple.com`, `icloud.com` → Apple (iOS/macOS)
  - `microsoft.com`, `windowsupdate.com` → Windows
- Shows **Last DNS** column in live table
- Logs notable domain queries to `logs/events.log`

### Phase 3.5 — MAC Seeding + Randomized MAC Detection
- Detects locally administered (randomized) MAC addresses using IEEE bit standard
- Shows `[rand] Randomized` instead of misleading `Unknown` for privacy MACs
- Seeds device table from `/proc/net/arp` at startup — instant population with no traffic required

### Phase 4 — New Device Alerts + Export *(current)*
- **New device alert**: terminal bell + highlighted print when an unseen MAC appears
- **Export to JSON**: `sudo python run.py --export devices.json`
- **Export to CSV**: `sudo python run.py --export devices.csv`
- All fields exported: IP, MAC, vendor, OS guess, TTL, hostname, DHCP fingerprint, DNS, timestamps

---

## Project Structure

```
lan-fingerprinter/
├── README.md
├── requirements.txt
├── run.py                  # Entry point — argument parsing, CWD setup
├── config.yaml             # Interface, DB path, feature flags
├── data/
│   ├── oui.csv             # IEEE OUI database (auto-downloaded, gitignored)
│   └── devices.db          # SQLite device store (gitignored)
├── logs/
│   └── events.log          # New devices, DHCP events, notable DNS queries
└── src/
    ├── __init__.py
    ├── main.py             # Orchestration, queue dispatch, live display, export
    ├── sniffer.py          # ARP + ICMP + DHCP + DNS capture (background thread)
    ├── oui.py              # OUI download, vendor lookup, MAC utils, ARP seeding
    ├── fingerprint.py      # OS resolution, device type inference (all signals)
    ├── dhcp.py             # DHCP option parser
    ├── dns.py              # DNS query parser + domain OS classification
    ├── database.py         # SQLite persistence (thread-safe)
    └── models.py           # Device dataclass
```

---

## Installation

### Requirements

- Python 3.10+
- Linux (tested on Kali Linux Rolling 2025.1)
- Root/sudo privileges (required for raw socket sniffing)

### Setup

```bash
git clone https://github.com/yourname/lan-fingerprinter.git
cd lan-fingerprinter
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**`requirements.txt`:**
```
scapy
rich
pyyaml
requests
```

---

## Configuration

`config.yaml`:

```yaml
interface: wlan0       # Network interface (run: ip link)
db_path: data/devices.db
update_interval: 2     # Table refresh interval in seconds
dhcp_enabled: true     # Enable passive DHCP fingerprinting
dns_enabled: true      # Enable passive DNS query tracking
```

Find your interface:
```bash
ip link show
```

---

## Running

### Live mode
```bash
sudo python run.py
```

On first run, the OUI database (~6MB) is automatically downloaded and cached. The kernel ARP cache is read immediately for instant device population. New devices trigger a terminal bell and highlighted alert.

To trigger device traffic for testing:
```bash
# In a second terminal — not required for passive operation
sudo nmap -sn 192.168.0.0/24
```

Press `Ctrl+C` to stop cleanly.

### Export mode

Export after running the sniffer (devices are persisted to SQLite):

```bash
# JSON export
sudo python run.py --export devices.json

# CSV export
sudo python run.py --export devices.csv

# Force format regardless of extension
sudo python run.py --export output.txt --format json
```

Export fields: `ip`, `mac`, `vendor`, `os_guess`, `device_type`, `ttl`, `hostname`, `dhcp_fingerprint`, `vendor_class`, `last_dns_domain`, `last_dns_time`, `first_seen`, `last_seen`.

---

## How It Works

lan-fingerprinter is **strictly passive** — it never sends packets.

### Signal pipeline

```
Network traffic
      │
      ├── ARP          → IP + MAC + OUI vendor lookup
      ├── ICMP reply   → TTL → OS family estimate
      ├── DHCP req     → hostname, vendor class, param list
      └── DNS query    → queried domain → platform inference
                                │
                         fingerprint.py
                    (priority: DHCP > DNS > TTL)
                                │
                          devices.db (SQLite)
                                │
                    Rich live terminal table
                    + logs/events.log
                    + JSON/CSV export
```

### Why passive matters

Active scanners (nmap, arp-scan) inject packets — triggering IDS alerts and potentially violating network policies. Passive fingerprinting observes only what devices naturally broadcast.

---

## Roadmap

- **Phase 5** — Classification confidence scoring (weight per signal, show confidence %)
- **Phase 6** — MAC spoofing detection (same IP, different MAC within short window)
- **Phase 7** — Local read-only web UI (Flask, 127.0.0.1 only)
- **Future** — TLS SNI extraction (passive domain tracking even with DoH)
- **Future** — Fingerbank DHCP param list lookup

---

## Development Guidelines

### Branching
```
main              ← stable only
feature/phase-X   ← one branch per phase
fix/description   ← targeted bug fixes
```

### Commit format
```
feat(scope): short description
fix(scope): short description
docs(readme): update for phase X
```

### Core rule
**Keep it passive.** No packet injection. No ARP requests. No pings. Observer only.

---

## Legal & Security Notice

For use **only on networks you own or have explicit permission to monitor**.

- **Kenya**: Subject to the [Kenya Data Protection Act, 2019](https://www.odpc.go.ke/dpa/) and the [Computer Misuse and Cybercrimes Act, 2018](https://www.ict.go.ke/computer-misuse-and-cybercrimes-act-2018/).
- All captured data stays on the local machine in `data/devices.db`. Nothing is transmitted externally.

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built on Kali Linux · Python · Scapy · Rich · SQLite*
