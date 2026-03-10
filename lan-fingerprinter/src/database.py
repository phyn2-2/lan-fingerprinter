import sqlite3
import threading
from datetime import datetime
from typing import Optional
from .models import Device


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
                        ip TEXT PRIMARY KEY,
                        mac TEXT NOT NULL,
                        vendor TEXT,
                        os_guess TEXT,
                        device_type TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        ttl INTEGER          -- Phase 1.5: extracted from ICMP echo reply IP header
                    )
                """)

    def update_or_insert_device(self, ip: str, mac: str, vendor: str = "Unknown",
                                os_guess: str = "Unknown", device_type: str = "Unknown",
                                ttl: Optional[int] = None):   # Phase 1.5: ttl param added
        now_iso = datetime.utcnow().isoformat()
        with self._lock:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO devices (ip, mac, vendor, os_guess, device_type, first_seen, last_seen, ttl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac         = excluded.mac,
                        vendor      = excluded.vendor,
                        os_guess    = excluded.os_guess,
                        device_type = excluded.device_type,
                        last_seen   = excluded.last_seen,
                        ttl         = CASE
                                        WHEN excluded.ttl IS NOT NULL THEN excluded.ttl
                                        ELSE devices.ttl
                                      END
                """, (ip, mac, vendor, os_guess, device_type, now_iso, now_iso, ttl))

    def update_ttl(self, ip: str, ttl: int):
        """Phase 1.5: Lightweight update — only write TTL for an existing device."""
        now_iso = datetime.utcnow().isoformat()
        with self._lock:
            with self.conn:
                self.conn.execute("""
                    UPDATE devices
                    SET ttl = ?, last_seen = ?
                    WHERE ip = ?
                """, (ttl, now_iso, ip))

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
                ttl=row[7] if len(row) > 7 else None   # Phase 1.5: read ttl column
            )
            devices.append(d)
        return devices

    def close(self):
        with self._lock:
            self.conn.close()
