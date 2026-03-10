from scapy.all import sniff, ARP, IP, ICMP, get_if_hwaddr, get_if_addr
from datetime import datetime, timezone
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
        self.my_ip = get_if_addr(interface)     # Phase 1.5 needed to skip self ICMP

    def start(self):
        print(f"[+] Starting passive ARP + ICMP sniffer on {self.interface} ...")
        t = threading.Thread(target=self._sniff_thread, daemon=True)
        t.start()

    def _sniff_thread(self):
        try:
            sniff(iface=self.interface,
                  filter="arp or icmp",     # Phase 1.5
                  prn=self._process_packet,
                  store=False)
        except Exception as e:
            print(f"[!] Sniffer error on {self.interface}: {e}")

    def _process_packet(self, pkt):
        # - - - ARP handling (unchanged from phase 1) - - -
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            now = datetime.now(timezone.utc)
            claimed_ip = arp.psrc
            claimed_mac = arp.hwsrc.lower()
            if claimed_mac == self.my_mac.lower():
                return
            self.packet_queue.put(("arp", claimed_ip, claimed_mac, now, arp.op))

        # - - - Phase 1.5: ICMP echo reply TTL extraction - - -
        elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
            if pkt[ICMP].type != 0:     # only echo reply (type 0)
                return
            ip_src = pkt[IP].src
            ttl = pkt[IP].ttl
            now = datetime.utcnow()

            if ip_src == self.my_ip:    # skip our own replies
                return

            self.packet_queue.put(("icmp", ip_src, ttl, now))


