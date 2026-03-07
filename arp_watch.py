from scapy.all import sniff, ARP

devices = {}

def process(packet):
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc           # protocol source = IP
        mac = packet[ARP].hwsrc         # hardware source = MAC

        if ip not in devices:
            devices[ip] = mac
            print(f"[NEW DEVICE] {ip} -> {mac}")
        else:
            if devices[ip] != mac:
                print(f"[WARNING] MAC CHANGED for {ip}")
                print(f"Old: {devices[ip]}")
                print(f"New: {mac}")
                devices[ip] = mac

sniff(filter="arp", prn=process, store=0)
