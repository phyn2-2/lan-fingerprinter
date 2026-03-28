"""
src/database.py — Thread-safe SQLite persistence layer
Phase 3 adds: last_dns_domain, last_dns_time columns
              update_dns() lightweight DNS-only update method
"""

import sqlite3
import threading
import logging
from datetime import datetime
from typing import Optional

from .models import Device

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._create_tables()

    def _create_tables(self):
        with self._lock:
            with self.conn:
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        ip               TEXT PRIMARY KEY,
                        mac              TEXT NOT NULL,
                        vendor           TEXT,
                        os_guess         TEXT,
                        device_type      TEXT,
                        first_seen       TEXT,
                        last_seen        TEXT,
                        ttl              INTEGER,   -- Phase 1.5: ICMP TTL
                        hostname         TEXT,      -- Phase 2: DHCP option 12
                        dhcp_fingerprint TEXT,      -- Phase 2: DHCP option 55
                        vendor_class     TEXT,      -- Phase 2: DHCP option 60
                        last_dns_domain  TEXT,      -- Phase 3: most recent DNS query
                        last_dns_time    TEXT       -- Phase 3: ISO timestamp of that query
                    )
                """)

    def update_or_insert_device(
        self,
        ip: str,
        mac: str,
        vendor: str = "Unknown",
        os_guess: str = "Unknown",
        device_type: str = "Unknown",
        ttl: Optional[int] = None,
        hostname: str = "",
        dhcp_fingerprint: str = "",
        vendor_class: str = "",
        last_dns_domain: str = "",
        last_dns_time: Optional[str] = None,
    ):
        now_iso = datetime.utcnow().isoformat()
        with self._lock:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO devices
                        (ip, mac, vendor, os_guess, device_type,
                         first_seen, last_seen, ttl,
                         hostname, dhcp_fingerprint, vendor_class,
                         last_dns_domain, last_dns_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac              = excluded.mac,
                        vendor           = excluded.vendor,
                        os_guess         = excluded.os_guess,
                        device_type      = excluded.device_type,
                        last_seen        = excluded.last_seen,
                        ttl              = CASE
                                             WHEN excluded.ttl IS NOT NULL THEN excluded.ttl
                                             ELSE devices.ttl
                                           END,
                        hostname         = CASE
                                             WHEN excluded.hostname != '' THEN excluded.hostname
                                             ELSE devices.hostname
                                           END,
                        dhcp_fingerprint = CASE
                                             WHEN excluded.dhcp_fingerprint != '' THEN excluded.dhcp_fingerprint
                                             ELSE devices.dhcp_fingerprint
                                           END,
                        vendor_class     = CASE
                                             WHEN excluded.vendor_class != '' THEN excluded.vendor_class
                                             ELSE devices.vendor_class
                                           END,
                        last_dns_domain  = CASE
                                             WHEN excluded.last_dns_domain != '' THEN excluded.last_dns_domain
                                             ELSE devices.last_dns_domain
                                           END,
                        last_dns_time    = CASE
                                             WHEN excluded.last_dns_domain != '' THEN excluded.last_dns_time
                                             ELSE devices.last_dns_time
                                           END
                """, (
                    ip, mac, vendor, os_guess, device_type,
                    now_iso, now_iso, ttl,
                    hostname, dhcp_fingerprint, vendor_class,
                    last_dns_domain, last_dns_time,
                ))

    def update_dns(self, ip: str, domain: str, dns_time: str):
        """
        Phase 3: Lightweight update — only write DNS fields for an existing device.
        Avoids touching vendor/OS/type data from an unrelated signal.
        No-op if device not yet in DB (ARP will add it when seen).
        """
        now_iso = datetime.utcnow().isoformat()
        with self._lock:
            with self.conn:
                self.conn.execute("""
                    UPDATE devices
                    SET last_dns_domain = ?,
                        last_dns_time   = ?,
                        last_seen       = ?
                    WHERE ip = ?
                """, (domain, dns_time, now_iso, ip))

    def get_all_devices(self) -> list[Device]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            rows = cursor.fetchall()

        devices = []
        for row in rows:
            def _col(idx, default=None):
                return row[idx] if len(row) > idx and row[idx] is not None else default

            last_dns_time_raw = _col(12)
            d = Device(
                ip=row[0],
                mac=row[1],
                vendor=row[2]         or "Unknown",
                os_guess=row[3]       or "Unknown",
                device_type=row[4]    or "Unknown",
                first_seen=datetime.fromisoformat(row[5]) if row[5] else None,
                last_seen=datetime.fromisoformat(row[6])  if row[6] else None,
                ttl=_col(7),
                hostname=_col(8, ""),
                dhcp_fingerprint=_col(9, ""),
                vendor_class=_col(10, ""),
                last_dns_domain=_col(11, ""),
                last_dns_time=datetime.fromisoformat(last_dns_time_raw)
                              if last_dns_time_raw else None,
            )
            devices.append(d)
        return devices

    def close(self):
        with self._lock:
            self.conn.close()
