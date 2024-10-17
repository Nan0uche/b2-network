# on importe la lib scapy
from scapy.all import *

# le potit ping
ping = ICMP(type=8)

# on met 1.1.1.1 en dst pour le paquet
packet = IP(src="10.33.72.147", dst="10.33.79.22")

# MAC src et dst bouge pas : la trame va de mon PC à la passerelle
frame = Ether(src="00:a5:54:c6:91:d4", dst="00:41:0e:2b:91:5d")

# craft trame finale
final_frame = frame/packet/ping

# send !
answers, unanswered_packets = srp(final_frame, timeout=10)

# print response !
print(f"Pong reçu : {answers[0]}")