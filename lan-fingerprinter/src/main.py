"""
src/main.py — Orchestration, queue dispatch, live display
Phase 4:
  - New device alert: terminal bell + print when unseen MAC appears
  - Export: --export devices.json / --export devices.csv
"""

import sys
import time
import json
import csv as csv_module
import logging
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional
import yaml
from queue import Queue

from rich.console import Console
from rich.table import Table
from rich.live import Live

from .sniffer import Sniffer
from .database import Database
from .oui import load_oui_db, get_vendor, is_randomized_mac, seed_from_arp_cache
from .fingerprint import resolve_os_guess, guess_type_from_all_signals
from .models import Device

# ── Logging ───────────────────────────────────────────────────────────────────
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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_notable(domain: str) -> bool:
    d = domain.lower()
    return any(p in d for p in NOTABLE_DOMAIN_PATTERNS)


def _resolve_vendor(mac: str, oui_db: dict) -> str:
    if is_randomized_mac(mac):
        return "[rand] Randomized"
    return get_vendor(mac, oui_db)


def _truncate(s: str, n: int = 28) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def load_config() -> dict:
    with open("config.yaml") as f:
        return yaml.safe_load(f)


# ── Export ────────────────────────────────────────────────────────────────────

def _device_to_dict(dev: Device) -> dict:
    return {
        "ip":               dev.ip,
        "mac":              dev.mac,
        "vendor":           dev.vendor,
        "os_guess":         dev.os_guess,
        "device_type":      dev.device_type,
        "ttl":              dev.ttl,
        "hostname":         dev.hostname,
        "dhcp_fingerprint": dev.dhcp_fingerprint,
        "vendor_class":     dev.vendor_class,
        "last_dns_domain":  dev.last_dns_domain,
        "last_dns_time":    dev.last_dns_time.isoformat() if dev.last_dns_time else None,
        "first_seen":       dev.first_seen.isoformat() if dev.first_seen else None,
        "last_seen":        dev.last_seen.isoformat()  if dev.last_seen  else None,
    }


def export_devices(devices: list[Device], path: str, fmt: Optional[str] = None):
    """
    Export device list to JSON or CSV.
    Format is inferred from file extension unless `fmt` is given explicitly.
    """
    p = Path(path)

    # Determine format
    if fmt:
        resolved_fmt = fmt
    elif p.suffix.lower() == ".json":
        resolved_fmt = "json"
    elif p.suffix.lower() == ".csv":
        resolved_fmt = "csv"
    else:
        console.print(
            f"[red][!] Cannot infer format from '{p.suffix}'. "
            f"Use --format json or --format csv.[/red]"
        )
        sys.exit(1)

    rows = [_device_to_dict(d) for d in devices]

    if resolved_fmt == "json":
        with open(p, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
        console.print(f"[green][+] Exported {len(rows)} device(s) to {p} (JSON).[/green]")

    elif resolved_fmt == "csv":
        if not rows:
            console.print("[yellow][!] No devices to export.[/yellow]")
            return
        fieldnames = list(rows[0].keys())
        with open(p, "w", newline="", encoding="utf-8") as f:
            writer = csv_module.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        console.print(f"[green][+] Exported {len(rows)} device(s) to {p} (CSV).[/green]")


# ── Table ─────────────────────────────────────────────────────────────────────

def generate_table(devices: list[Device]) -> Table:
    table = Table(title="LAN Devices (Passive ARP + ICMP + DHCP + DNS Discovery)")
    table.add_column("IP",         style="cyan",        no_wrap=True)
    table.add_column("MAC",        style="magenta",     no_wrap=True)
    table.add_column("Hostname",   style="bright_white")
    table.add_column("Vendor",     style="green")
    table.add_column("OS Guess",   style="yellow")
    table.add_column("TTL",        style="red",         no_wrap=True)
    table.add_column("Type",       style="blue")
    table.add_column("Last DNS",   style="bright_cyan")
    table.add_column("First Seen", style="dim",         no_wrap=True)
    table.add_column("Last Seen",  style="dim",         no_wrap=True)

    for dev in devices:
        table.add_row(
            dev.ip,
            dev.mac,
            dev.hostname or "-",
            dev.vendor if dev.vendor else "Unknown",
            dev.os_guess,
            str(dev.ttl) if dev.ttl is not None else "-",
            dev.device_type,
            _truncate(dev.last_dns_domain) if dev.last_dns_domain else "-",
            dev.first_seen.strftime("%H:%M:%S") if dev.first_seen else "-",
            dev.last_seen.strftime("%H:%M:%S")  if dev.last_seen  else "-",
        )
    return table


# ── New device alert ──────────────────────────────────────────────────────────

def _alert_new_device(ip: str, mac: str, hostname: str):
    """
    Phase 4: Alert when a completely new MAC is seen for the first time this run.
    Prints to terminal and rings the bell. Also logs to events.log.
    """
    label = hostname if hostname else "Unknown"
    msg = f"[+] NEW DEVICE DETECTED: {ip} - {mac} - {label}"
    print("\a", end="", flush=True)          # terminal bell
    console.print(f"[bold bright_yellow]{msg}[/bold bright_yellow]")
    logger.info(f"NEW_DEVICE | {msg}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main(args=None):
    config       = load_config()
    interface    = config["interface"]
    db_path      = config["db_path"]
    interval     = config["update_interval"]
    dhcp_enabled = config.get("dhcp_enabled", True)
    dns_enabled  = config.get("dns_enabled", True)

    db     = Database(db_path)
    oui_db = load_oui_db()

    # ── Export mode (Phase 4) ─────────────────────────────────────────────────
    if args and args.export:
        devices = db.get_all_devices()
        if not devices:
            console.print("[yellow][!] No devices in DB yet. Run the sniffer first.[/yellow]")
            sys.exit(0)
        export_devices(devices, args.export, getattr(args, "format", None))
        sys.exit(0)

    # ── Live mode ─────────────────────────────────────────────────────────────

    # Seed from kernel ARP cache (passive, instant population)
    n = seed_from_arp_cache(db, oui_db)
    if n:
        print(f"[+] Seeded {n} device(s) from /proc/net/arp.")

    # Track MACs seen this run for new-device alerts
    seen_macs: set[str] = {dev.mac for dev in db.get_all_devices()}

    packet_queue = Queue()
    sniffer = Sniffer(interface, db, packet_queue)
    sniffer.start()

    def _get_existing(ip: str) -> Optional[Device]:
        return next((d for d in db.get_all_devices() if d.ip == ip), None)

    def _check_new(mac: str, ip: str, hostname: str = ""):
        """Fire alert if this MAC has not been seen in this session."""
        if mac and mac not in seen_macs and mac != "00:00:00:00:00:00":
            seen_macs.add(mac)
            _alert_new_device(ip, mac, hostname)

    def update_display():
        devices = db.get_all_devices()
        for dev in devices:
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

                    # ── ARP ───────────────────────────────────────────────
                    if tag == "arp":
                        _, ip, mac, timestamp, op = item
                        vendor = _resolve_vendor(mac, oui_db)
                        existing = _get_existing(ip)
                        # Phase 4: alert before writing so hostname may be blank
                        # — DHCP will enrich it later if available
                        _check_new(mac, ip, existing.hostname if existing else "")
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

                    # ── ICMP TTL ──────────────────────────────────────────
                    elif tag == "icmp":
                        _, ip, ttl, timestamp = item
                        existing = _get_existing(ip)
                        os_guess = resolve_os_guess(
                            ttl,
                            existing.hostname        if existing else "",
                            existing.vendor_class    if existing else "",
                            existing.last_dns_domain if existing else "",
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess,
                            existing.vendor          if existing else "Unknown",
                            existing.hostname        if existing else "",
                            existing.vendor_class    if existing else "",
                            existing.last_dns_domain if existing else "",
                        )
                        if existing:
                            db.update_or_insert_device(
                                ip, existing.mac, existing.vendor,
                                os_guess, device_type, ttl,
                                existing.hostname, existing.dhcp_fingerprint,
                                existing.vendor_class, existing.last_dns_domain,
                                existing.last_dns_time.isoformat()
                                    if existing.last_dns_time else None,
                            )
                        else:
                            db.update_or_insert_device(
                                ip, "00:00:00:00:00:00", "Unknown",
                                os_guess, "Unknown", ttl,
                            )
                        live.update(update_display())

                    # ── DHCP ──────────────────────────────────────────────
                    elif tag == "dhcp" and dhcp_enabled:
                        _, ip, mac, hostname, vendor_class, param_list, timestamp = item
                        vendor = _resolve_vendor(mac, oui_db)
                        existing = _get_existing(ip) or _get_existing("")
                        current_ttl = existing.ttl             if existing else None
                        current_dns = existing.last_dns_domain if existing else ""
                        os_guess = resolve_os_guess(
                            current_ttl, hostname, vendor_class, current_dns
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess, vendor, hostname, vendor_class, current_dns
                        )
                        effective_ip = ip if ip else (existing.ip if existing else mac)
                        # Phase 4: DHCP may reveal hostname of already-seen MAC
                        _check_new(mac, effective_ip, hostname)
                        db.update_or_insert_device(
                            effective_ip, mac, vendor,
                            os_guess, device_type, current_ttl,
                            hostname, param_list, vendor_class, current_dns,
                            existing.last_dns_time.isoformat()
                                if (existing and existing.last_dns_time) else None,
                        )
                        logger.info(
                            f"DHCP | ip={effective_ip} mac={mac} "
                            f"hostname={hostname!r} vendor_class={vendor_class!r} "
                            f"os_guess={os_guess!r}"
                        )
                        live.update(update_display())

                    # ── DNS ───────────────────────────────────────────────
                    elif tag == "dns" and dns_enabled:
                        _, ip, mac, domain, query_type, timestamp = item
                        dns_time_iso = timestamp.isoformat()
                        existing = _get_existing(ip)
                        if not existing:
                            # Device not yet seen via ARP — discard (no ghost records)
                            continue
                        db.update_dns(ip, domain, dns_time_iso)
                        os_guess = resolve_os_guess(
                            existing.ttl, existing.hostname,
                            existing.vendor_class, domain,
                        )
                        device_type = guess_type_from_all_signals(
                            os_guess, existing.vendor,
                            existing.hostname, existing.vendor_class, domain,
                        )
                        if (os_guess != existing.os_guess
                                or device_type != existing.device_type):
                            db.update_or_insert_device(
                                ip, existing.mac, existing.vendor,
                                os_guess, device_type, existing.ttl,
                                existing.hostname, existing.dhcp_fingerprint,
                                existing.vendor_class, domain, dns_time_iso,
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
