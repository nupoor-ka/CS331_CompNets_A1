import scapy
import pandas as pd
import datetime
import json
from scapy.all import rdpcap, DNS, DNSQR


#loading packets that are only dns
dns_packets = rdpcap("C:/Users/user/Desktop/CN_assignment1/dns_only.pcap")
def make_header(seq):
  now = datetime.datetime.now()
  header = now.strftime("%H%M%S") + f"{seq:02d}"
  return header.encode()

print(len(dns_packets))
def make_header(seq):
  now = datetime.datetime.now()
  header = now.strftime("%H%M%S") + f"{seq:02d}"
  return header.encode()

custom_packets=[]
for seq, pkt in enumerate(dns_packets):
  header= make_header(seq)
  original_dns=pkt[DNS].qd.qname.decode()
  custom_packet =  header / pkt
  custom_packets.append(custom_packet)

IP_Pool= [
  "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
  "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
  "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
  ]

with open("C:/Users/user/Desktop/CN_assignment1/rules.json", "r") as f:
    config = json.load(f)

rules = config["timestamp_rules"]["time_based_routing"]

def get_ip_address(header):
    for seq, pkt in enumerate(custom_packets):
        timestamp= make_header(seq)
        hours=int(timestamp[0:1])
        if 4 <= hours <= 11:
            rule = rules["morning"]
        elif 12 <= hours <= 19: 
            rule = rules["afternoon"]
        else:               
            rule = rules["night"]
        id=int(timestamp[-2:])
        hash_val = id % rule["hash_mod"]
        index = rule["ip_pool_start"] + hash_val
    return IP_Pool[index]


table= []
for seq, pkt in enumerate(custom_packets):
  header = make_header(seq)
  query_name = pkt[DNSQR].qname.decode()
  ip = get_ip_address(custom_packets)
  table.append({
            "Custom header value (HHMMSSID)": header,
            "Domain name": query_name,
            "Resolved IP address": ip
        })
  
df= pd.DataFrame(table)

df.to_csv("C:/Users/user/Desktop/CN_assignment1/dns_report.csv", index=False)