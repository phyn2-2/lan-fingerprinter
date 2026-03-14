"""
src/models.py — Device dataclass
Phase 2 adds: hostname, dhcp_fingerprint, vendor_class
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    device_type: str = "Unknown"
    first_seen: datetime = None
    last_seen: datetime = None
    ttl: Optional[int] = None               # Phase 1.5: from ICMP echo reply
    hostname: str = ""                       # Phase 2: DHCP option 12
    dhcp_fingerprint: str = ""              # Phase 2: DHCP option 55 param list
    vendor_class: str = ""                  # Phase 2: DHCP option 60
