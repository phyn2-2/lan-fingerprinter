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
    ttl: Optional[int] = None       # Phase 1.5: populated from ICMP echo replies

