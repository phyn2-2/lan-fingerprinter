"""
src/main.py — Orchestration, queue dispatch, live display
Phase 3.5:
  - Show "[rand] Randomized" vendor for locally administered MACs
  - DNS handler: only update if device already known via ARP (no ghost records)
  - Seed from /proc/net/arp at startup for instant table population
"""

import time
import logging
from typing import Optional
import yaml
from queue import Queue

from rich.console import Console
from rich.table import Table
from rich.live import Live

from .sniffer import Sniffer
from .database import Database
from .oui import load_oui_db, get_vendor, is_randomized_mac, seed_from_arp_cache
from .fingerprint import (
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

NOTABLE_DOMAIN_PATTERNS = (
    "microsoft", "windows", "apple", "android", "gstatic",
    "googleapis", "icloud", "ubuntu", "debian", "archlinux",
    "openwrt", "github", "amazonaws", "cloudflare",
)


def _is_notable(domain: str) -> bool:
    d = domain.lower()
    return any(p in d for p in NOTABLE_DOMAIN_PATTERNS)


def _resolve_vendor(mac: str, oui_db: dict) -> str:
    """
    Phase 3.5: Return vendor string with randomized MAC awareness.
    Randomized MACs will never match OUI — show honest label instead.
    """
    if is_randomized_mac(mac):
        return "[rand] Randomized"
    return get_vendor(mac, oui_db)


def load_config():
    with open("config.yaml") as f:
        return yaml.safe_load(f)


def _truncate(s: str, n: int = 28) -> str:
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
    table.add_column("Last DNS",   style="bright_cyan")
    table.add_column("First Seen", style="dim",          no_wrap=True)
    table.add_column("Last Seen",  style="dim",          no_wrap=True)

    for dev in devices:
        # Phase 3.5: vendor display — use stored value which already has [rand] if applicable
        vendor_display = dev.vendor if dev.vendor else "Unknown"

        table.add_row(
            dev.ip,
            dev.mac,
            dev.hostname or "-",
            vendor_display,
            dev.os_guess,
            str(dev.ttl) if dev.ttl is not None else "-",
            dev.device_type,
            _truncate(dev.last_dns_domain) if dev.last_dns_domain else "-",
            dev.first_seen.strftime("%H:%M:%S") if dev.first_seen else "-",
            dev.last_seen.strftime("%H:%M:%S")  if dev.last_seen  else "-",
        )
    return table


def main():
    config       = load_config()
    interface    = config["interface"]
    db_path      = config["db_path"]
    interval     = config["update_interval"]
    dhcp_enabled = config.get("dhcp_enabled", True)
    dns_enabled  = config.get("dns_enabled", True)

    db     = Database(db_path)
    oui_db = load_oui_db()

    # ── Phase 3.5: Seed from kernel ARP cache before sniffer starts ──────────
    n = seed_from_arp_cache(db, oui_db)
    if n:
        print(f"[+] Seeded {n} device(s) from /proc/net/arp.")

    packet_queue = Queue()
    sniffer = Sniffer(interface, db, packet_queue)
    sniffer.start()

    def _get_existing(ip: str) -> Optional[Device]:
        return next((d for d in db.get_all_devices() if d.ip == ip), None)

    def update_display():
        devices = db.get_all_devices()
        for dev in devices:
            # Refresh vendor if still raw Unknown (seeded records with real MACs)
            if dev.vendor == "Unknown":
                vendor = _resolve_vendor(dev.mac, oui_db)
                if vendor != dev.vendor:
                    db.update_or_insert_device(
                        dev.ip, dev.mac, vendor,
                        dev.os_guess, dev.device_type, dev.ttl,
                        dev.hostname, dev.dhcp_fingerprint, dev.vendor_class,
                        dev.last_dns_domain,
                        dev.last_dns_time.isoformat() if dev.last_dns_time else None,
                    )
        return generate_table(db.get_all_devices())

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
                        # Phase 3.5: randomized MAC aware vendor resolution
                        vendor = _resolve_vendor(mac, oui_db)
                        existing = _get_existing(ip)
                        db.update_or_insert_device(
                            ip, mac, vendor,
                            existing.os_guess         if existing else "Unknown",
                            existing.device_type      if existing else "Unknown",
                            existing.ttl              if existing else None,
                            existing.hostname         if existing else "",
                            existing.dhcp_fingerprint if existing else "",
                            existing.vendor_class     if existing else "",
                            existing.last_dns_domain  if existing else "",
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
                            existing.hostname         if existing else "",
                            existing.vendor_class     if existing else "",
                            existing.last_dns_domain  if existing else "",
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess,
                            existing.vendor           if existing else "Unknown",
                            existing.hostname         if existing else "",
                            existing.vendor_class     if existing else "",
                            existing.last_dns_domain  if existing else "",
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
                        vendor = _resolve_vendor(mac, oui_db)
                        existing = _get_existing(ip) or _get_existing("")
                        current_ttl = existing.ttl            if existing else None
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

                        # Phase 3.5: ONLY update if device is already known via ARP.
                        # If ip not in DB, drop this DNS record — do not create a
                        # ghost record using MAC as IP placeholder.
                        existing = _get_existing(ip)
                        if not existing:
                            # Device not yet seen via ARP — discard silently.
                            # It will be correlated once ARP registers the IP.
                            continue

                        db.update_dns(ip, domain, dns_time_iso)

                        # Re-resolve OS + type with new DNS signal
                        os_guess = resolve_os_guess(
                            existing.ttl, existing.hostname,
                            existing.vendor_class, domain,
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess, existing.vendor,
                            existing.hostname, existing.vendor_class,
                            domain,
                        )
                        if (os_guess != existing.os_guess
                                or device_type != existing.device_type):
                            db.update_or_insert_device(
                                ip, existing.mac, existing.vendor,
                                os_guess, device_type, existing.ttl,
                                existing.hostname, existing.dhcp_fingerprint,
                                existing.vendor_class,
                                domain, dns_time_iso,
                            )

                        if _is_notable(domain):
                            logger.info(
                                f"DNS  | ip={ip} mac={existing.mac} "
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
