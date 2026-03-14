"""
src/sniffer.py — Passive packet capture
Phase 1:   ARP  → IP + MAC
Phase 1.5: ICMP → TTL → OS guess
Phase 2:   DHCP → hostname, vendor_class, param_list
"""

from scapy.all import sniff, ARP, IP, ICMP, UDP, get_if_hwaddr, get_if_addr
from datetime import datetime, timezone
import threading
import logging
from queue import Queue

from .models import Device
from .database import Database
from .fingerprint import guess_os_from_ttl, get_vendor
from .dhcp import parse_dhcp_options                   # Phase 2

logger = logging.getLogger(__name__)


class Sniffer:
    def __init__(self, interface, db: Database, packet_queue: Queue):
        self.interface = interface
        self.db = db
        self.packet_queue = packet_queue
        self.my_mac = get_if_hwaddr(interface)
        self.my_ip = get_if_addr(interface)

    def start(self):
        print(f"[+] Starting passive ARP + ICMP + DHCP sniffer on {self.interface} ...")
        t = threading.Thread(target=self._sniff_thread, daemon=True)
        t.start()

    def _sniff_thread(self):
        try:
            sniff(
                iface=self.interface,
                filter="arp or icmp or (udp and (port 67 or port 68))",  # Phase 2: DHCP
                prn=self._process_packet,
                store=False,
            )
        except Exception as e:
            print(f"[!] Sniffer error on {self.interface}: {e}")
            logger.error(f"Sniffer error on {self.interface}: {e}")

    def _process_packet(self, pkt):
        # --- ARP (Phase 1) ---
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            now = datetime.now(timezone.utc)
            claimed_ip = arp.psrc
            claimed_mac = arp.hwsrc.lower()
            if claimed_mac == self.my_mac.lower():
                return
            self.packet_queue.put(("arp", claimed_ip, claimed_mac, now, arp.op))

        # --- ICMP echo reply (Phase 1.5) ---
        elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
            if pkt[ICMP].type != 0:
                return
            ip_src = pkt[IP].src
            ttl = pkt[IP].ttl
            now = datetime.utcnow()
            if ip_src == self.my_ip:
                return
            self.packet_queue.put(("icmp", ip_src, ttl, now))

        # --- DHCP Discover / Request (Phase 2) ---
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            # DHCP client → server: src=68, dst=67
            if not (sport == 68 and dport == 67):
                return
            result = parse_dhcp_options(pkt)
            if result is None:
                return
            mac = result["mac"]
            if not mac or mac == self.my_mac.lower():
                return
            now = datetime.utcnow()
            self.packet_queue.put((
                "dhcp",
                result["ip"],       # may be "" on first Discover
                mac,
                result["hostname"],
                result["vendor_class"],
                result["param_list"],
                now,
            ))
