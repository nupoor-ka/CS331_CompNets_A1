# CS 331 : Computer Networks
# Assignment 1
### Vyomika Vasireddy (23110363) and Nupoor Assudani (23110224)

We worked with file 0.pcap. The sum of the last 3 digits of both our roll numbers is (3 + 6 + 3 + 2 + 2 + 4) = 20 and 20 % 10 = 0, hence 0.pcap.

Our fist step was filtering out the DNS queries from this file. For this, we used wireshark with the filter "dns && dns.flags.response==0" and exported these filtered packets as "0_dns_queries.pcap".
