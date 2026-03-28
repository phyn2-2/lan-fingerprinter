"""
src/main.py — Orchestration, queue dispatch, live display
Phase 3: DNS queue handler, Last DNS column, domain-based OS refinement
"""

import time
import logging
import yaml
from queue import Queue

from rich.console import Console
from typing import Optional
from rich.table import Table
from rich.live import Live

from .sniffer import Sniffer
from .database import Database
from .oui import load_oui_db
from .fingerprint import (
    get_vendor,
    resolve_os_guess,
    guess_type_from_all_signals,
)
from .models import Device

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    filename="logs/events.log",
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

console = Console()

# Domains worth logging — anything suggesting platform identity or external comms
NOTABLE_DOMAIN_PATTERNS = (
    "microsoft", "windows", "apple", "android", "gstatic",
    "googleapis", "icloud", "ubuntu", "debian", "archlinux",
    "openwrt", "github", "amazonaws", "cloudflare",
)


def _is_notable(domain: str) -> bool:
    d = domain.lower()
    return any(p in d for p in NOTABLE_DOMAIN_PATTERNS)


def load_config():
    with open("config.yaml") as f:
        return yaml.safe_load(f)


def _truncate(s: str, n: int = 28) -> str:
    """Truncate long domain names for the table column."""
    return s if len(s) <= n else s[:n - 1] + "…"


def generate_table(devices: list[Device]) -> Table:
    table = Table(title="LAN Devices (Passive ARP + ICMP + DHCP + DNS Discovery)")
    table.add_column("IP",         style="cyan",         no_wrap=True)
    table.add_column("MAC",        style="magenta",      no_wrap=True)
    table.add_column("Hostname",   style="bright_white")
    table.add_column("Vendor",     style="green")
    table.add_column("OS Guess",   style="yellow")
    table.add_column("TTL",        style="red",          no_wrap=True)
    table.add_column("Type",       style="blue")
    table.add_column("Last DNS",   style="bright_cyan")  # Phase 3
    table.add_column("First Seen", style="dim",          no_wrap=True)
    table.add_column("Last Seen",  style="dim",          no_wrap=True)

    for dev in devices:
        table.add_row(
            dev.ip,
            dev.mac,
            dev.hostname or "-",
            dev.vendor,
            dev.os_guess,
            str(dev.ttl) if dev.ttl is not None else "-",
            dev.device_type,
            _truncate(dev.last_dns_domain) if dev.last_dns_domain else "-",
            dev.first_seen.strftime("%H:%M:%S") if dev.first_seen else "-",
            dev.last_seen.strftime("%H:%M:%S")  if dev.last_seen  else "-",
        )
    return table


def main():
    config        = load_config()
    interface     = config["interface"]
    db_path       = config["db_path"]
    interval      = config["update_interval"]
    dhcp_enabled  = config.get("dhcp_enabled", True)
    dns_enabled   = config.get("dns_enabled", True)     # Phase 3 config key

    db           = Database(db_path)
    oui_db       = load_oui_db()
    packet_queue = Queue()

    sniffer = Sniffer(interface, db, packet_queue)
    sniffer.start()

    def _get_existing(ip: str) -> Optional[Device]:
        return next((d for d in db.get_all_devices() if d.ip == ip), None)

    def update_display():
        devices = db.get_all_devices()
        for dev in devices:
            if dev.vendor == "Unknown":
                dev.vendor = get_vendor(dev.mac, oui_db)
                db.update_or_insert_device(
                    dev.ip, dev.mac, dev.vendor,
                    dev.os_guess, dev.device_type, dev.ttl,
                    dev.hostname, dev.dhcp_fingerprint, dev.vendor_class,
                    dev.last_dns_domain,
                    dev.last_dns_time.isoformat() if dev.last_dns_time else None,
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
                            existing.os_guess      if existing else "Unknown",
                            existing.device_type   if existing else "Unknown",
                            existing.ttl           if existing else None,
                            existing.hostname      if existing else "",
                            existing.dhcp_fingerprint if existing else "",
                            existing.vendor_class  if existing else "",
                            existing.last_dns_domain if existing else "",
                            existing.last_dns_time.isoformat()
                                if (existing and existing.last_dns_time) else None,
                        )
                        live.update(update_display())

                    # ── ICMP TTL (Phase 1.5) ──────────────────────────────
                    elif tag == "icmp":
                        _, ip, ttl, timestamp = item
                        existing = _get_existing(ip)
                        os_guess = resolve_os_guess(
                            ttl,
                            existing.hostname      if existing else "",
                            existing.vendor_class  if existing else "",
                            existing.last_dns_domain if existing else "",
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess,
                            existing.vendor        if existing else "Unknown",
                            existing.hostname      if existing else "",
                            existing.vendor_class  if existing else "",
                            existing.last_dns_domain if existing else "",
                        )
                        if existing:
                            db.update_or_insert_device(
                                ip, existing.mac, existing.vendor,
                                os_guess, device_type, ttl,
                                existing.hostname, existing.dhcp_fingerprint,
                                existing.vendor_class,
                                existing.last_dns_domain,
                                existing.last_dns_time.isoformat()
                                    if existing.last_dns_time else None,
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
                        existing = _get_existing(ip) or _get_existing("")
                        current_ttl = existing.ttl if existing else None
                        current_dns = existing.last_dns_domain if existing else ""
                        os_guess = resolve_os_guess(
                            current_ttl, hostname, vendor_class, current_dns
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess, vendor, hostname, vendor_class, current_dns
                        )
                        effective_ip = ip if ip else (existing.ip if existing else mac)
                        db.update_or_insert_device(
                            effective_ip, mac, vendor,
                            os_guess, device_type, current_ttl,
                            hostname, param_list, vendor_class,
                            current_dns,
                            existing.last_dns_time.isoformat()
                                if (existing and existing.last_dns_time) else None,
                        )
                        logger.info(
                            f"DHCP | ip={effective_ip} mac={mac} "
                            f"hostname={hostname!r} vendor_class={vendor_class!r} "
                            f"os_guess={os_guess!r}"
                        )
                        live.update(update_display())

                    # ── DNS (Phase 3) ─────────────────────────────────────
                    elif tag == "dns" and dns_enabled:
                        _, ip, mac, domain, query_type, timestamp = item
                        dns_time_iso = timestamp.isoformat()

                        # Lightweight path: just update DNS fields if device known
                        existing = _get_existing(ip)
                        if existing:
                            db.update_dns(ip, domain, dns_time_iso)

                            # Re-resolve OS and type with new DNS signal
                            os_guess = resolve_os_guess(
                                existing.ttl, existing.hostname,
                                existing.vendor_class, domain,
                            )
                            device_type = guess_type_from_all_signals(
                                os_guess, existing.vendor,
                                existing.hostname, existing.vendor_class,
                                domain,
                            )
                            # Only write back if classification changed
                            if os_guess != existing.os_guess or device_type != existing.device_type:
                                db.update_or_insert_device(
                                    ip, existing.mac, existing.vendor,
                                    os_guess, device_type, existing.ttl,
                                    existing.hostname, existing.dhcp_fingerprint,
                                    existing.vendor_class,
                                    domain, dns_time_iso,
                                )
                        else:
                            # Device not yet seen via ARP — store DNS-only record
                            # MAC may be empty if Ethernet layer was missing
                            if mac:
                                vendor = get_vendor(mac, oui_db)
                            else:
                                vendor = "Unknown"
                            db.update_or_insert_device(
                                ip, mac or "00:00:00:00:00:00", vendor,
                                "Unknown", "Unknown", None,
                                "", "", "",
                                domain, dns_time_iso,
                            )

                        if _is_notable(domain):
                            logger.info(
                                f"DNS  | ip={ip} mac={mac or '?'} "
                                f"domain={domain!r} type={query_type}"
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
