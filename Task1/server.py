import pandas as pd
import json
from scapy.all import *
import os

dnsq_w_hdr = "dnsq_cli_hdr.pcap" # dns queries with custom client headers
op_csv = "ip_table.csv" # output table has custom header, domain name, resolved ip

# defining the custom header, same as on client side
class CustomHeader(Packet): # needed to create a custom header so scapy found it correctly
    """
    A custom header with 
    """
    name = "CustomHeader"
    fields_desc = [StrFixedLenField("timestamp_id", b"", length=8)]  # 8 byte field

split_layers(UDP, DNS) # need to remove the default assumption that DNS is after UDP
bind_layers(UDP, CustomHeader) # defining the location of custom header for scapy
bind_layers(CustomHeader, DNS)

def get_ip_address(header, rules, ip_pool): # rules should be rules["timestamp_rules"]["time_based_routing"]
    hrs=int(header[0:1]) # hdr starts with HH
    ip_start_val = 0
    for name in rules.keys():
        start_str, end_str = rules[name]["time_range"].split("-")
        start = int(start_str[0:2]) # first hour of the range
        end = int(end_str[0:2])  # last hour of the range

        if start <= end:  # same day range
            if start <= hrs <= end:
                ip_start_val = rules[name]["ip_pool_start"]
        else:  # overnight range, wraps midnight
            if hrs >= start or hrs <= end:
                ip_start_val = rules[name]["ip_pool_start"]
    id = int(header[-2:]) # last two digits are id
    id_mod = id % 5
    return ip_pool[ip_start_val+id_mod]


if not os.path.exists(dnsq_w_hdr):
    print(f"file with packets from client, {dnsq_w_hdr}, not found")
else:
    with open("rules.json", "r") as f:
        config = json.load(f)

    rules = config["timestamp_rules"]["time_based_routing"]

    IP_Pool= [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
    ]

    table=[]

    pkts = rdpcap(dnsq_w_hdr)
    print("sample summary of packets")
    print(pkts[0].summary())
    print()
    for pkt in pkts:
        query_name = pkt[DNSQR].qname.decode()
        timestamp = pkt[CustomHeader].timestamp_id # scapy recognises the custom header now
        header = timestamp.decode() # converting bytes to string
        ip = get_ip_address(header,rules,IP_Pool)
        table.append({"Custom header value (HHMMSSID)": header,
                      "Domain name": query_name,
                      "Resolved IP address": ip})

    df= pd.DataFrame(table)
    df.to_csv(op_csv, index=False)
    print(f"table with custom headers, queried domain names and resolved ip addresses stored in {op_csv}\n")
    print(df.head(5))
