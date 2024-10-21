from scapy.all import *
from collections import deque

MAX_PAYLOAD_SIZE = 56

received_chunks = {}

def packet_callback(packet):
    if packet.haslayer(ICMP) and packet[ICMP].payload:
        payload = bytes(packet[ICMP].payload)
        seq_num = int.from_bytes(payload[:4], 'big')
        chunk = payload[4:]

        if seq_num not in received_chunks:
            received_chunks[seq_num] = chunk
            print(f"Morceau ICMP reçu : {chunk}")

def save_received_file(output_path):
    with open(output_path, 'wb') as f:
        for i in sorted(received_chunks.keys()):
            f.write(received_chunks[i])

print("Démarrage du sniffing ICMP.")

try:
    sniff(filter="icmp", prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nArrêt du sniffing.")
finally:
    output_path = "received_image.jpg"
    save_received_file(output_path)
    print(f"Fichier reçu sauvegardé sous : {output_path}")
