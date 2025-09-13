# CS 331 : Computer Networks
# Assignment 1
### Vyomika Vasireddy (23110363) and Nupoor Assudani (23110224)

We worked with file 0.pcap. The sum of the last 3 digits of both our roll numbers is (3 + 6 + 3 + 2 + 2 + 4) = 20 and 20 % 10 = 0, hence 0.pcap.

Our fist step was filtering out the DNS queries from this file. For this, we used wireshark with the filter "dns && dns.flags.response==0" and exported these filtered packets as "0_dns_queries.pcap". This was to understand the kind of information these files provided and how we could use wireshark for parsing them.

This repository has two files, "client.py" and "server.py". The original pcap file, say "input.pcap" (here "0.pcap"), with all packets should be given to "client.py". It will then filterout the DNS queries and store them in a separate file, "0_dnsq.pcap". It then opens this file, as an input file, and another output file, "0_dnsq_mod.pcap". It parses through the DNS query packets and stores those packets with custom headers in the output file.

The file "0_dnsq_mod.pcap" is now given as input to "server.py". It reads the packets with the custom header and finds the IP address from the given pool following the specified rules and stres the extracted information in "dns_table.csv".
