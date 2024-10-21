from scapy.all import *
from collections import deque

MAX_PAYLOAD_SIZE = 56

received_chunks = deque()

def packet_callback(packet):
    if packet.haslayer(ICMP) and packet[ICMP].payload:
        payload = bytes(packet[ICMP].payload).decode(errors='ignore')
        if payload:
            received_chunks.append(payload)
            print(f"Données ICMP reçues : {payload}")

        if len(received_chunks) > 0:
            full_message = ''.join(received_chunks)
            print(f"Message reconstruit : {full_message}")

print("Démarrage du sniffing ICMP.")
try:
    sniff(filter="icmp", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nArrêt du sniffing.")
