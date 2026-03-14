"""
src/database.py — Thread-safe SQLite persistence layer
Phase 2 adds: hostname, dhcp_fingerprint, vendor_class columns
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
                        ip              TEXT PRIMARY KEY,
                        mac             TEXT NOT NULL,
                        vendor          TEXT,
                        os_guess        TEXT,
                        device_type     TEXT,
                        first_seen      TEXT,
                        last_seen       TEXT,
                        ttl             INTEGER,    -- Phase 1.5: ICMP echo reply IP TTL
                        hostname        TEXT,       -- Phase 2: DHCP option 12
                        dhcp_fingerprint TEXT,      -- Phase 2: DHCP option 55 param list
                        vendor_class    TEXT        -- Phase 2: DHCP option 60
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
    ):
        now_iso = datetime.utcnow().isoformat()
        with self._lock:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO devices
                        (ip, mac, vendor, os_guess, device_type,
                         first_seen, last_seen, ttl,
                         hostname, dhcp_fingerprint, vendor_class)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac              = excluded.mac,
                        vendor           = excluded.vendor,
                        os_guess         = excluded.os_guess,
                        device_type      = excluded.device_type,
                        last_seen        = excluded.last_seen,
                        -- Preserve TTL unless a new one is provided
                        ttl              = CASE
                                             WHEN excluded.ttl IS NOT NULL THEN excluded.ttl
                                             ELSE devices.ttl
                                           END,
                        -- Prefer non-empty DHCP fields over existing empty ones
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
                                           END
                """, (
                    ip, mac, vendor, os_guess, device_type,
                    now_iso, now_iso, ttl,
                    hostname, dhcp_fingerprint, vendor_class,
                ))

    def get_all_devices(self) -> list[Device]:
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
            rows = cursor.fetchall()
        devices = []
        for row in rows:
            d = Device(
                ip=row[0],
                mac=row[1],
                vendor=row[2],
                os_guess=row[3],
                device_type=row[4],
                first_seen=datetime.fromisoformat(row[5]) if row[5] else None,
                last_seen=datetime.fromisoformat(row[6]) if row[6] else None,
                ttl=row[7] if len(row) > 7 else None,
                hostname=row[8] if len(row) > 8 and row[8] else "",
                dhcp_fingerprint=row[9] if len(row) > 9 and row[9] else "",
                vendor_class=row[10] if len(row) > 10 and row[10] else "",
            )
            devices.append(d)
        return devices

    def close(self):
        with self._lock:
            self.conn.close()
