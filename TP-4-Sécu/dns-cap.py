from scapy.all import sniff, DNS, DNSQR, DNSRR

def capture_dns_response(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        if packet[DNSQR].qname == b'ynov.com.':
            print(f"Adresse IP de ynov.com : {packet[DNSRR].rdata}")


sniff(filter="udp port 53", prn=capture_dns_response, store=0)