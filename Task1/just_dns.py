import scapy
from scapy.all import wrpcap, rdpcap, DNS, DNSQR

packets = rdpcap("C:/Users/user/Desktop/CN_assignment1/0.pcap")

dns_packets = []

for pkt in packets:
    if not pkt.haslayer(DNS):
        continue
    dns_layer = pkt[DNS]
    if dns_layer.qr == 0 and dns_layer.qdcount == 1:
        dns_packets.append(pkt)

wrpcap("C:/Users/user/Desktop/CN_assignment1/dns_only.pcap", dns_packets)