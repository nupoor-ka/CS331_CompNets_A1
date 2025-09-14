# CS 331 : Computer Networks
# Assignment 1
### Vyomika Vasireddy (23110363) and Nupoor Assudani (23110224)

We worked with file _0.pcap_. The sum of the last 3 digits of both our roll numbers is (3 + 6 + 3 + 2 + 2 + 4) = 20 and 20 % 10 = 0, hence _0.pcap_.

Our fist step was filtering out the DNS queries from this file. For this, we used wireshark with the filter _dns && dns.flags.response==0_ and exported these filtered packets as _0_dns_queries.pcap_. This was to understand the kind of information these files provided and how we could use wireshark for parsing them.

This repository has two python script files, _client.py_ and _server.py_. The original pcap file, say _input.pcap_ (here _0.pcap_), with all packets should be given to _client.py_. It will then filterout the DNS queries and store them in a separate file, _dns_queries.pcap_. It then opens this file, as an input file, and another output file, _dnsq_cli_hdr.pcap_. It parses through the DNS query packets and stores those packets with custom headers in the output file.

The file _dnsq_cli_hdr.pcap_ is now given as input to _server.py_. It reads the packets with the custom header and finds the IP address from the given pool following the specified rules and adds the extracted information in _ip_table.csv_.

To add the custom header right after DNS, we had to create a new layer using scapy, termed CustomHeader, and defined it on both the client and server side.
