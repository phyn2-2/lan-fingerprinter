from scapy.all import sniff, ARP, IP, get_if_hwaddr
from datetime import datetime
import threading
from queue import Queue
from .models import Device
from .database import Database
from .fingerprint import guess_os_from_ttl, get_vendor

class Sniffer:
    def __init__(self, interface, db: Database, packet_queue: Queue):
        self.interface = interface
        self.db = db
        self.packet_queue = packet_queue
        self.my_mac = get_if_hwaddr(interface)

    def start(self):
        print(f"[+] Starting passive ARP sniffer on {self.interface} ...")
        t = threading.Thread(target=self._sniff_thread, daemon=True)
        t.start()

    def _sniff_thread(self):
        try:
            sniff(iface=self.interface,
                  filter="arp",
                  prn=self._process_packet,
                  store=False)
        except Exception as e:
            print(f"[!] Sniffer error on {self.interface}: {e}")

    def _process_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        now = datetime.now(timezone.utc)

        # We care about who is claiming what IP
        claimed_ip = arp.psrc
        claimed_mac = arp.hwsrc.lower()

        # Skip our own MAC to avoid self-loop noise
        if claimed_mac == self.my_mac.lower():
            return

        # Enqueue for main thread processing (avoids Scapy thread issues)
        self.packet_queue.put((claimed_ip, claimed_mac, now, arp.op))
