import time
import yaml
from queue import Queue
from rich.console import Console
from rich.table import Table
from rich.live import Live
from .sniffer import Sniffer
from .database import Database
from .oui import load_oui_db
from .fingerprint import get_vendor, guess_os_from_ttl, guess_type_from_os_and_vendor  # Phase 1.5
from .models import Device

console = Console()


def load_config():
    with open("config.yaml") as f:
        return yaml.safe_load(f)


def generate_table(devices: list[Device]) -> Table:
    table = Table(title="LAN Devices (Passive ARP Discovery)")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="green")
    table.add_column("OS Guess", style="yellow")
    table.add_column("TTL", style="red")       # Phase 1.5: TTL column
    table.add_column("Type", style="blue")
    table.add_column("First Seen", style="dim")
    table.add_column("Last Seen", style="dim")
    for dev in devices:
        table.add_row(
            dev.ip,
            dev.mac,
            dev.vendor,
            dev.os_guess,
            str(dev.ttl) if dev.ttl is not None else "-",   # Phase 1.5: render TTL
            dev.device_type,
            dev.first_seen.strftime("%H:%M:%S") if dev.first_seen else "-",
            dev.last_seen.strftime("%H:%M:%S") if dev.last_seen else "-"
        )
    return table


def main():
    config = load_config()
    interface = config["interface"]
    db = Database(config["db_path"])
    oui_db = load_oui_db()
    packet_queue = Queue()
    sniffer = Sniffer(interface, db, packet_queue)
    sniffer.start()

    def update_display():
        devices = db.get_all_devices()
        for dev in devices:
            # Vendor lookup (run once or cache)
            if dev.vendor == "Unknown":
                dev.vendor = get_vendor(dev.mac, oui_db)
                db.update_or_insert_device(dev.ip, dev.mac, dev.vendor,
                                           dev.os_guess, dev.device_type, dev.ttl)
        return generate_table(devices)

    with Live(console=console, refresh_per_second=0.5) as live:
        live.update(update_display())
        while True:
            try:
                if not packet_queue.empty():
                    item = packet_queue.get()

                    if item[0] == "arp":
                        # item = ("arp", ip, mac, timestamp, op)
                        _, ip, mac, timestamp, op = item
                        vendor = get_vendor(mac, oui_db)
                        db.update_or_insert_device(ip, mac, vendor)
                        live.update(update_display())

                    elif item[0] == "icmp":
                        # Phase 1.5: item = ("icmp", ip, ttl, timestamp)
                        _, ip, ttl, timestamp = item
                        os_guess = guess_os_from_ttl(ttl)

                        # Try to get existing device to preserve vendor/mac
                        existing = next(
                            (d for d in db.get_all_devices() if d.ip == ip), None
                        )
                        if existing:
                            # Update OS guess and type now that we have TTL
                            device_type = guess_type_from_os_and_vendor(os_guess, existing.vendor)
                            db.update_or_insert_device(
                                ip, existing.mac, existing.vendor,
                                os_guess, device_type, ttl
                            )
                        else:
                            # Device seen via ICMP before ARP — store with placeholder MAC
                            db.update_or_insert_device(
                                ip, "00:00:00:00:00:00", "Unknown",
                                os_guess, "Unknown", ttl
                            )
                        live.update(update_display())

                time.sleep(config["update_interval"])
                live.update(update_display())
            except KeyboardInterrupt:
                console.print("\n[+] Stopping lan-fingerprinter...")
                db.close()
                break


if __name__ == "__main__":
    main()
