# CS 331 : Computer Networks
# Assignment 1
### Vyomika Vasireddy (23110363) and Nupoor Assudani (23110224)

We worked with file 0.pcap. The sum of the last 3 digits of both our roll numbers is (3 + 6 + 3 + 2 + 2 + 4) = 20 and 20 % 10 = 0, hence 0.pcap.

Our fist step was filtering out the DNS queries from this file. For this, we used wireshark with the filter "dns && dns.flags.response==0" and exported these filtered packets as "0_dns_queries.pcap". This was to understand the kind of information these files provided and how we could use wireshark for parsing them.

This repository has two python script files, "client.py" and "server.py". The original pcap file, say "input.pcap" (here "0.pcap"), with all packets should be given to "client.py". It will then filterout the DNS queries and store them in a separate file, "dns_queries.pcap". It then opens this file, as an input file, and another output file, "dnsg_cli_hdr.pcap". It parses through the DNS query packets and stores those packets with custom headers in the output file.

The file "dnsq_cli_hdr.pcap" is now given as input to "server.py". It reads the packets with the custom header and finds the IP address from the given pool following the specified rules and adds the extracted information in "ip_table.csv".

To add the custom header right after DNS, we had to create a new layer using scapy, termed CustomHeader, and defined it on both the client and server side.