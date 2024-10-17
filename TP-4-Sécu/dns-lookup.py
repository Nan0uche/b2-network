from scapy.all import *

ip = IP(dst="1.1.1.1")
udp = UDP(dport=53)
dns = DNS(qd=DNSQR(qname="ynov.com"))

req = ip/udp/dns

ans = sr1(req, timeout=10)

ans.show()