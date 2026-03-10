# lan-fingerprinter

A passive LAN device fingerprinter that identifies, tracks, and classifies devices on your local network using ARP observation and ICMP TTL analysis (with DHCP fingerprinting planned), without transmitting a single packet.

The tool operates purely as a network observer, making it suitable for research, learning, and passive network monitoring.

---

# Features

## Phase 1 — Passive ARP Discovery

- Sniffs ARP traffic on any interface (WiFi or Ethernet)
- Extracts IP address, MAC address, and ARP operation type per device
- Resolves MAC OUI prefix → vendor name via the IEEE database (auto-downloaded)
- Persists discovered devices to SQLite with `first_seen` and `last_seen` timestamps
- Displays a live terminal table powered by the Rich library with automatic refresh

---

## Phase 1.5 — ICMP TTL OS Fingerprinting

Passively captures ICMP echo replies (type 0) from devices already communicating on the LAN.

Extracts the TTL value from the IP header to infer an OS family.

| TTL | OS Guess |
|-----|----------|
| 64 | Linux / Android / macOS |
| 128 | Windows |
| 255 | Router / Cisco / IoT |
| 50–70 | Likely Linux-like |
| 120–140 | Likely Windows-like |

The system combines vendor + OS guess to infer device type classification such as:

- Router
- Mobile device
- Laptop / workstation
- Single-board computer
- IoT device

TTL values are stored in the database and the OS Guess and Device Type columns update live.

---

# Project Structure

lan-fingerprinter/
├── README.md
├── requirements.txt
├── run.py                  # Entry point (sets working directory and calls main)
├── config.yaml             # Interface, database path, refresh interval
├── data/
│   ├── oui.csv             # IEEE OUI database (auto-downloaded, gitignored)
│   └── devices.db          # SQLite device store (gitignored)
├── logs/                   # Reserved for future logging (gitignored)
└── src/
    ├── __init__.py
    ├── main.py             # Orchestration, live display, queue dispatch
    ├── sniffer.py          # Scapy ARP + ICMP packet capture (background thread)
    ├── oui.py              # OUI download + MAC → vendor lookup
    ├── fingerprint.py      # TTL → OS guess, vendor + OS → device type
    ├── database.py         # SQLite persistence layer (thread-safe)
    └── models.py           # Device dataclass

---

# Installation

## Requirements

- Python 3.10+
- Linux (tested on Kali Linux Rolling 2025.1)
- Root / sudo privileges (required for raw packet sniffing)

---

## Setup

Clone the repository:

git clone https://github.com/yourname/lan-fingerprinter.git  
cd lan-fingerprinter

Create a virtual environment:

python -m venv venv

Activate the environment:

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

---

## Dependencies (requirements.txt)

scapy  
rich  
pyyaml  
requests  

Scapy → packet sniffing and protocol parsing  
Rich → terminal UI rendering  
PyYAML → configuration parsing  
Requests → OUI database download

---

# Configuration

Edit `config.yaml` before running:

interface: wlan0  
db_path: data/devices.db  
update_interval: 2  

Field descriptions:

interface → network interface to sniff  
db_path → SQLite database location  
update_interval → terminal table refresh rate (seconds)

To identify your interface:

ip link show

---

# Running

sudo python run.py

On the first execution the tool downloads the IEEE OUI vendor database (~6 MB) and stores it locally in:

data/oui.csv

Subsequent runs reuse the cached file.

---

# Optional Traffic Trigger

Passive mode means devices appear only when they communicate.

To accelerate discovery during testing you can generate traffic using:

sudo nmap -sn 192.168.0.0/24

This generates ARP and ICMP traffic that the fingerprinter can observe.

---

# Example Output

              LAN Devices (Passive ARP Discovery)

┌───────────────┬───────────────────┬──────────────────┬────────────────────────────┬─────┬──────────────┬──────────┬──────────┐
│ IP            │ MAC               │ Vendor           │ OS Guess                   │ TTL │ Type         │ First    │ Last     │
├───────────────┼───────────────────┼──────────────────┼────────────────────────────┼─────┼──────────────┼──────────┼──────────┤
│ 192.168.0.1   │ 04:95:e6:24:b0:a0 │ Tenda Technology │ Router / IoT / Cisco       │ 255 │ Router / AP  │ 12:01:03 │ 12:18:44 │
│ 192.168.0.106 │ 9a:18:63:61:63:2d │ Unknown          │ Linux / Android / macOS    │ 64  │ Mobile       │ 12:01:05 │ 12:18:44 │
│ 192.168.0.128 │ 78:45:61:ff:c1:db │ CyberTAN Tech    │ Linux / Android / macOS    │ 64  │ Router / AP  │ 12:01:07 │ 12:18:44 │
│ 192.168.0.102 │ 00:28:f8:46:1d:fb │ Intel Corporate  │ Windows (TTL 128)          │ 128 │ Windows PC   │ 12:01:09 │ 12:18:44 │
└───────────────┴───────────────────┴──────────────────┴────────────────────────────┴─────┴──────────────┴──────────┴──────────┘

Press Ctrl+C to exit cleanly.

---

# How It Works

lan-fingerprinter operates entirely in passive observation mode.

It analyzes packets already present on the network.

Signal pipeline:

Network Traffic  
│  
├── ARP packets → IP + MAC extraction  
│        │  
│        ▼  
│   OUI lookup → Vendor  
│        │  
└── ICMP replies → TTL extraction → OS guess  
         │  
         ▼  
   Device classification  
         │  
         ▼  
   SQLite database (devices.db)  
         │  
         ▼  
   Rich live terminal display

---

# Why Passive Fingerprinting Matters

Active scanners generate traffic and may:

- Trigger intrusion detection systems
- Violate network policy
- Create unnecessary network load

Passive monitoring observes only natural device communication, making it useful for:

- network research
- security analysis
- educational experiments
- infrastructure monitoring

---

# Roadmap

## Phase 2 — Passive DHCP Fingerprinting (Next)

The tool will sniff DHCP Discover and Request packets when devices join the network.

Fields to extract:

Option 60 → Vendor Class Identifier  
Option 12 → Hostname  
Option 55 → Parameter Request List  

These values enable more accurate OS detection using fingerprint datasets such as Fingerbank.

Data will be stored per device in the database.

---

## Future Phases

Phase 3 — Passive DNS tracking  
Observe DNS queries (port 53) to identify device behaviors.

Phase 4 — Classification engine  
Score-based classification combining signals from:

ARP  
ICMP  
DHCP  
DNS  

Phase 5 — New device alerts  
Notify when an unknown MAC address appears.

Phase 6 — Optional web interface  
A read-only LAN dashboard built using Flask or FastAPI.

---

# Development Guidelines

Branch strategy:

main  
feature/phase-X  
fix/description  

---

Commit message format:

type(scope): description

Examples:

feat(sniffer): add passive ICMP TTL extraction  
fix(oui): handle HTML response from maclookup.app  
refactor(database): replace INSERT OR REPLACE with proper upsert  
docs(readme): update roadmap with Phase 2 DHCP plan  

---

# Core Principle

Keep the system passive.

The tool must:

- never inject packets
- never send ARP requests
- never ping devices

It should remain a pure network observer.

Active scanning features should exist only in a separate mode if ever implemented.

---

# Code Guidelines

- Each module has a single responsibility
- Sniffer thread communicates via Queue only
- Database layer uses thread locks
- Public functions use type hints
- Complex logic is documented with inline comments

---

# Legal & Security Notice

This tool is intended for educational and research purposes on networks you own or are authorized to monitor.

In Kenya, use is subject to:

Kenya Data Protection Act (2019)  
Computer Misuse and Cybercrimes Act (2018)

Unauthorized monitoring of networks may be illegal.

Users are responsible for ensuring they have permission before deploying this tool.

The application does not transmit data externally.  
All data is stored locally in `data/devices.db`.

---

# License

MIT License — see LICENSE.

---

Built with Python · Scapy · Rich · SQLite · Kali Linux
