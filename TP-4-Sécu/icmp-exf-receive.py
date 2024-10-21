from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(ICMP) and packet[ICMP].payload:
        payload = bytes(packet[ICMP].payload)
        print(f"Données ICMP reçues : {payload.decode(errors='ignore')}")

print("Démarrage du sniffing ICMP.")

try:
    sniff(filter="icmp", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nArrêt du sniffing.")
