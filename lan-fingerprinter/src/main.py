"""
src/main.py — Orchestration, queue dispatch, live display
Phase 2: DHCP queue handling, hostname column, event logging
"""

import time
import logging
import yaml
from queue import Queue

from rich.console import Console
from rich.table import Table
from rich.live import Live

from .sniffer import Sniffer
from .database import Database
from .oui import load_oui_db
from .fingerprint import (
    get_vendor,
    guess_os_from_ttl,
    guess_os_from_dhcp,
    guess_type_from_all_signals,
)
from .models import Device

# ── Logging setup (Phase 2) ──────────────────────────────────────────────────
logging.basicConfig(
    filename="logs/events.log",
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

console = Console()


def load_config():
    with open("config.yaml") as f:
        return yaml.safe_load(f)


def generate_table(devices: list[Device]) -> Table:
    table = Table(title="LAN Devices (Passive ARP + ICMP + DHCP Discovery)")
    table.add_column("IP",         style="cyan")
    table.add_column("MAC",        style="magenta")
    table.add_column("Hostname",   style="bright_white")   # Phase 2
    table.add_column("Vendor",     style="green")
    table.add_column("OS Guess",   style="yellow")
    table.add_column("TTL",        style="red")
    table.add_column("Type",       style="blue")
    table.add_column("First Seen", style="dim")
    table.add_column("Last Seen",  style="dim")

    for dev in devices:
        table.add_row(
            dev.ip,
            dev.mac,
            dev.hostname or "-",
            dev.vendor,
            dev.os_guess,
            str(dev.ttl) if dev.ttl is not None else "-",
            dev.device_type,
            dev.first_seen.strftime("%H:%M:%S") if dev.first_seen else "-",
            dev.last_seen.strftime("%H:%M:%S") if dev.last_seen else "-",
        )
    return table


def main():
    config = load_config()
    interface     = config["interface"]
    db_path       = config["db_path"]
    interval      = config["update_interval"]
    dhcp_enabled  = config.get("dhcp_enabled", True)      # Phase 2 config key

    db       = Database(db_path)
    oui_db   = load_oui_db()
    packet_queue = Queue()

    sniffer = Sniffer(interface, db, packet_queue)
    sniffer.start()

    def _get_existing(ip: str):
        """Return Device from DB matching ip, or None."""
        return next((d for d in db.get_all_devices() if d.ip == ip), None)

    def update_display():
        devices = db.get_all_devices()
        for dev in devices:
            if dev.vendor == "Unknown":
                dev.vendor = get_vendor(dev.mac, oui_db)
                db.update_or_insert_device(
                    dev.ip, dev.mac, dev.vendor,
                    dev.os_guess, dev.device_type,
                    dev.ttl, dev.hostname, dev.dhcp_fingerprint, dev.vendor_class,
                )
        return generate_table(devices)

    with Live(console=console, refresh_per_second=0.5) as live:
        live.update(update_display())
        while True:
            try:
                if not packet_queue.empty():
                    item = packet_queue.get()
                    tag = item[0]

                    # ── ARP (Phase 1) ─────────────────────────────────────
                    if tag == "arp":
                        _, ip, mac, timestamp, op = item
                        vendor = get_vendor(mac, oui_db)
                        existing = _get_existing(ip)
                        db.update_or_insert_device(
                            ip, mac, vendor,
                            existing.os_guess if existing else "Unknown",
                            existing.device_type if existing else "Unknown",
                            existing.ttl if existing else None,
                            existing.hostname if existing else "",
                            existing.dhcp_fingerprint if existing else "",
                            existing.vendor_class if existing else "",
                        )
                        live.update(update_display())

                    # ── ICMP TTL (Phase 1.5) ──────────────────────────────
                    elif tag == "icmp":
                        _, ip, ttl, timestamp = item
                        os_guess = guess_os_from_ttl(ttl)
                        existing = _get_existing(ip)
                        if existing:
                            device_type = guess_type_from_all_signals(
                                os_guess, existing.vendor,
                                existing.hostname, existing.vendor_class,
                            )
                            db.update_or_insert_device(
                                ip, existing.mac, existing.vendor,
                                os_guess, device_type, ttl,
                                existing.hostname, existing.dhcp_fingerprint,
                                existing.vendor_class,
                            )
                        else:
                            db.update_or_insert_device(
                                ip, "00:00:00:00:00:00", "Unknown",
                                os_guess, "Unknown", ttl,
                            )
                        live.update(update_display())

                    # ── DHCP (Phase 2) ────────────────────────────────────
                    elif tag == "dhcp" and dhcp_enabled:
                        _, ip, mac, hostname, vendor_class, param_list, timestamp = item

                        vendor = get_vendor(mac, oui_db)

                        # DHCP OS guess takes priority; fall back to TTL guess
                        existing = _get_existing(ip) or _get_existing("")
                        current_ttl = existing.ttl if existing else None
                        dhcp_os = guess_os_from_dhcp(hostname, vendor_class)
                        os_guess = dhcp_os if dhcp_os else guess_os_from_ttl(current_ttl)

                        device_type = guess_type_from_all_signals(
                            os_guess, vendor, hostname, vendor_class
                        )

                        # Use ARP-learned IP if DHCP has no IP yet (Discover stage)
                        effective_ip = ip if ip else (existing.ip if existing else mac)

                        db.update_or_insert_device(
                            effective_ip, mac, vendor,
                            os_guess, device_type, current_ttl,
                            hostname, param_list, vendor_class,
                        )

                        logger.info(
                            f"DHCP | ip={effective_ip} mac={mac} "
                            f"hostname={hostname!r} vendor_class={vendor_class!r} "
                            f"params={param_list!r} os_guess={os_guess!r}"
                        )
                        live.update(update_display())

                time.sleep(interval)
                live.update(update_display())

            except KeyboardInterrupt:
                console.print("\n[+] Stopping lan-fingerprinter...")
                logger.info("lan-fingerprinter stopped by user.")
                db.close()
                break


if __name__ == "__main__":
    main()
