from scapy.all import *

def dns_sniffer(packet):
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode('utf-8')
        hidden_data = query.split('.')[0]
        print(f"Chaîne cachée reçue : {hidden_data}")

print("Démarrage du sniffing DNS sur le port 53.")
sniff(filter="udp port 53", prn=dns_sniffer, store=0)
