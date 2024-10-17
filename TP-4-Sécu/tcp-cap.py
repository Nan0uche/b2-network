from scapy.all import sniff

def print_it_please(packet):
    if packet.haslayer('IP') and packet.haslayer('ICMP'):
        packet_source_ip = packet['IP'].src
        packet_destination_ip = packet['IP'].dst
        icmp_type = packet['ICMP'].type
        icmp_code = packet['ICMP'].code

        print(f"Packet ICMP reçu !")
        print(f"Adresse IP src : {packet_source_ip}")
        print(f"Adresse IP dst : {packet_destination_ip}")
        print(f"Type ICMP : {icmp_type}")
        print(f"Code ICMP : {icmp_code}")

sniff(filter="icmp and src host 1.1.1.1", prn=print_it_please, count=1)
