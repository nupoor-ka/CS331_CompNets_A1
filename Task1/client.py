# the client has to take the original pcap file, get dns queries, format with custom header and store

from datetime import datetime
from scapy.all import *
import os

allpkts = "C:/Users/nupoo/Downloads/7.pcap" # first pcap, with all packets
dnsq = "dns_queries.pcap" # pcap with dns queries
dnsq_w_hdr = "dnsq_cli_hdr.pcap" # dns queries with custom client headers

if not os.path.exists(dnsq): # creating this only if it doesn't exist, this is a long step
    packets = rdpcap(allpkts)
    dns_packets = []
    for pkt in packets:
        if not pkt.haslayer(DNS): # check if this packet has a dns header
            continue
        dns_layer = pkt[DNS]
        if dns_layer.qr == 0 and dns_layer.qdcount == 1: # check if it's a query
            dns_packets.append(pkt)
    print(f"stored dns queries in {dnsq}\n")
    wrpcap(dnsq, dns_packets)

dns_packets = rdpcap(dnsq)
print(f"found {len(dns_packets)} dns queries\n")

class CustomHeader(Packet): # needed to create a custom header so scapy found it correctly
    name = "CustomHeader"
    fields_desc = [StrFixedLenField("timestamp_id", b"", length=8)]  # 8 byte field

bind_layers(UDP, CustomHeader) # defining the location of custom header for scapy
bind_layers(CustomHeader, DNS)

def make_header(seq): # HHMMSSID
    now = datetime.now()
    header = now.strftime("%H%M%S") + f"{seq:02d}"
    return CustomHeader(timestamp_id=header.encode()) # created acc that header class

custom_packets=[]

print("sample of packet structure")
print(dns_packets[0].summary())
print()

for seq, pkt in enumerate(dns_packets):
    header=make_header(seq)
    header.add_payload(pkt[DNS])
    pkt[UDP].remove_payload()
    pkt[UDP].add_payload(header)
    layer = pkt.firstlayer()
    del pkt[UDP].len # need to remove len, chksum so it recalculates
    del pkt[UDP].chksum # we've changed the payloads for udp, ip and ether
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[Ether].len
    del pkt[Ether].chksum
    custom_packets.append(pkt)

print("sample structure of queries stored")
print(custom_packets[0].summary())
print()

wrpcap(dnsq_w_hdr, custom_packets)
print(f"wrote dns query packets with custom client header to {dnsq_w_hdr}")
