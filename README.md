# CS 331 : Computer Networks
# Assignment 1
### Vyomika Vasireddy (23110363) and Nupoor Assudani (23110224)

We worked with file _7.pcap_. The sum of the last 3 digits of both our roll numbers is (363 + 224) and __7 % 10 = 7, hence _7.pcap_.

As a sanity check, and to understand how wireshark works, we used it to filter out the DNS queries from this file. For this, we used the filter _dns && dns.flags.response==0_. This was to understand the kind of information these files provided and how we could use wireshark for parsing them.

This repository has two python script files, _client.py_ and _server.py_. The original pcap file, say _input.pcap_ (here _7.pcap_), with all packets should be given to _client.py_. It will then filterout the DNS queries and store them in a separate file, _dns_queries.pcap_. It then opens this file, as an input file, and another output file, _dnsq_cli_hdr.pcap_. It parses through the DNS query packets and stores those packets with custom headers in the output file.

---


<img width="777" height="281" alt="ss of client.py op" src="https://github.com/user-attachments/assets/0b763a2c-d77d-4cc2-bf8b-84f88d973707" />

-----------

The file _dnsq_cli_hdr.pcap_ is now given as input to _server.py_. It reads the packets with the custom header and finds the IP address from the given pool following the specified rules and adds the extracted information in _ip_table.csv_.

----------------------

<img width="1068" height="283" alt="ss of server.py op" src="https://github.com/user-attachments/assets/8885f464-2f56-44e4-8f7b-28f75ef56f77" />

-------------------

To add the custom header right after DNS, we had to create a new layer using scapy, termed CustomHeader, and defined it on both the client and server side.
