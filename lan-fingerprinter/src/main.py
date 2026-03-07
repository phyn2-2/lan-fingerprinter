import time
import yaml
from queue import Queue
from rich.console import Console
from rich.table import Table
from rich.live import Live
from .sniffer import Sniffer
from .database import Database
from .oui import load_oui_db
from .fingerprint import get_vendor
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
    table.add_column("Type", style="blue")
    table.add_column("First Seen", style="dim")
    table.add_column("Last Seen", style="dim")
    for dev in devices:
        table.add_row(
            dev.ip,
            dev.mac,
            dev.vendor,
            dev.os_guess,
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
                db.update_or_insert_device(dev.ip, dev.mac, dev.vendor, dev.os_guess, dev.device_type)
        return generate_table(devices)
    with Live(console=console, refresh_per_second=0.5) as live:
        live.update(update_display())
        while True:
            try:
                if not packet_queue.empty():
                    ip, mac, timestamp, op = packet_queue.get()
                    # Update DB
                    db.update_or_insert_device(ip, mac)
                    live.update(update_display())
                time.sleep(config["update_interval"])
                live.update(update_display())
            except KeyboardInterrupt:
                console.print("\n[+] Stopping lan-fingerprinter...")
                break
if __name__ == "__main__":
    main()
