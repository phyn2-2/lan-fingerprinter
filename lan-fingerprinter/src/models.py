"""
src/models.py — Device dataclass
Phase 3 adds: last_dns_domain, last_dns_time
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
    ttl: Optional[int] = None               # Phase 1.5: ICMP echo reply IP TTL
    hostname: str = ""                       # Phase 2: DHCP option 12
    dhcp_fingerprint: str = ""              # Phase 2: DHCP option 55 param list
    vendor_class: str = ""                  # Phase 2: DHCP option 60
    last_dns_domain: str = ""               # Phase 3: most recent notable DNS query
    last_dns_time: Optional[datetime] = None  # Phase 3: timestamp of that query
