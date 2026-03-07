from scapy.all import *

packet = IP(dst="8.8.8.8")/ICMP()

reply = sr1(packet)

reply.show()


