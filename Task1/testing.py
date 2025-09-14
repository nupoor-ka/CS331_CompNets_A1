from scapy.all import *
dnsq = "dns_queries.pcap" # pcap with dns queries
dns_packets = rdpcap(dnsq)
for i in range(len(dns_packets)):
    print(dns_packets[i].summary())

for seq, pkt in enumerate(dns_packets):
    header=make_header(seq)
    header.add_payload(pkt[DNS])
    pkt[UDP].remove_payload()
    pkt[UDP].add_payload(header)
    layer = pkt.firstlayer()
    while not isinstance(layer, NoPayload):
        if 'chksum' in layer.default_fields:
            del layer.chksum
        if 'len' in layer.default_fields:
            del layer.len
    custom_packets.append(pkt)
    # tried every way, still had to create a new packet
    # dns = DNS(id=pkt[DNS].id, # had to create this again because just reusing the old one wasn't working
    #                 qr=pkt[DNS].qr,
    #                 opcode=pkt[DNS].opcode,
    #                 aa=pkt[DNS].aa,
    #                 tc=pkt[DNS].tc,
    #                 rd=pkt[DNS].rd,
    #                 ra=pkt[DNS].ra,
    #                 z=pkt[DNS].z,
    #                 ad=pkt[DNS].ad,
    #                 cd=pkt[DNS].cd,
    #                 rcode=pkt[DNS].rcode,
    #                 qdcount=pkt[DNS].qdcount,
    #                 ancount=pkt[DNS].ancount,
    #                 nscount=pkt[DNS].nscount,
    #                 arcount=pkt[DNS].arcount,
    #                 qd=DNSQR(qname=pkt[DNS].qd.qname,
    #                         qtype=pkt[DNS].qd.qtype,
    #                         unicastresponse = pkt[DNS].qd.unicastresponse,
    #                         qclass=pkt[DNS].qd.qclass))
    # udp = UDP(sport = pkt[UDP].sport, dport = pkt[UDP].dport)
    # ip = IP(version=pkt[IP].version,
    #         ihl = pkt[IP].ihl,
    #         tos=pkt[IP].tos,
    #         id=pkt[IP].id,
    #         flags=pkt[IP].flags,
    #         frag=pkt[IP].frag,
    #         ttl=pkt[IP].ttl,
    #         proto=pkt[IP].proto,
    #         src=pkt[IP].src,
    #         dst=pkt[IP].dst)
    # ether = Ether(dst=pkt[Ether].dst,src=pkt[Ether].src,type=pkt[Ether].type)
    # newpkt = ether/ip/udp/header/dns
    # custom_packets.append(newpkt)