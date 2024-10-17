## I. Getting started Scapy

**☀️ [ping.py](./ping.py)**
```
nanouche@Ubuntu:~$ sudo python3 ping.py 
Begin emission:
Finished sending 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
Pong reçu : QueryAnswer(query=<Ether  dst=7c:5a:1c:d3:d8:76 src=00:a5:54:c6:91:d4 type=IPv4 |<IP  frag=0 proto=icmp src=10.33.72.147 dst=1.1.1.1 |<ICMP  type=echo-request |>>>, answer=<Ether  dst=00:a5:54:c6:91:d4 src=7c:5a:1c:d3:d8:76 type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=28 id=38317 flags= frag=0 ttl=55 proto=icmp chksum=0x997e src=1.1.1.1 dst=10.33.72.147 |<ICMP  type=echo-reply code=0 chksum=0x0 id=0x0 seq=0x0 |<Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' |>>>>)
```
**☀️ [tcp-cap.py](./tcp-cap.py)**  
On lance **[tcp-cap.py](./tcp-cap.py)** dans un premier Terminal et dans un second, on lance **[tcp-cap.py](./tcp-cap.py)**
```
nanouche@Ubuntu:~$ sudo python3 tcp-cap.py 
Packet ICMP reçu !
Adresse IP src : 1.1.1.1
Adresse IP dst : 10.33.72.147
Type ICMP : 0
Code ICMP : 0
```
**☀️ [dns-cap.py](./dns-cap.py)**  
On ```dig ynov.com``` dans un premier Terminal et dans un second, on lance **[tcp-cap.py](./tcp-cap.py)**
```
nanouche@Ubuntu:~$ sudo python3 dns-cap.py
Adresse IP de ynov.com : 172.67.74.226
```
**☀️ [dns-lookup.py](./dns-lookup.py)**
```
nanouche@Ubuntu:~$ sudo python3 dns-lookup.py
Begin emission:
Finished sending 1 packets.
.....*
Received 6 packets, got 1 answers, remaining 0 packets
###[ IP ]### 
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 102
  id        = 6201
  flags     = DF
  frag      = 0
  ttl       = 55
  proto     = udp
  chksum    = 0xd698
  src       = 1.1.1.1
  dst       = 10.33.72.147
  \options   \
###[ UDP ]### 
     sport     = domain
     dport     = domain
     len       = 82
     chksum    = 0x4d5f
###[ DNS ]### 
        id        = 0
        qr        = 1
        opcode    = QUERY
        aa        = 0
        tc        = 0
        rd        = 1
        ra        = 1
        z         = 0
        ad        = 0
        cd        = 0
        rcode     = ok
        qdcount   = 1
        ancount   = 3
        nscount   = 0
        arcount   = 0
        \qd        \
         |###[ DNS Question Record ]### 
         |  qname     = 'ynov.com.'
         |  qtype     = A
         |  qclass    = IN
        \an        \
         |###[ DNS Resource Record ]### 
         |  rrname    = 'ynov.com.'
         |  type      = A
         |  rclass    = IN
         |  ttl       = 300
         |  rdlen     = 4
         |  rdata     = 104.26.11.233
         |###[ DNS Resource Record ]### 
         |  rrname    = 'ynov.com.'
         |  type      = A
         |  rclass    = IN
         |  ttl       = 300
         |  rdlen     = 4
         |  rdata     = 104.26.10.233
         |###[ DNS Resource Record ]### 
         |  rrname    = 'ynov.com.'
         |  type      = A
         |  rclass    = IN
         |  ttl       = 300
         |  rdlen     = 4
         |  rdata     = 172.67.74.226
        ns        = None
        ar        = None
```
## II. ARP Poisoning
**☀️ [arp-poisoning.py](./arp-poisoning.py)**  
Fait en collaboration avec ROUSSEL Mathéo. De plus on ping au préalable la victime pour connaître son ip et sa MAC puis après on flush la table arp pour pouvoir la redonner.

#### Mon PC :
```
nanouche@Ubuntu:/media/nanouche/SANDISK USB/Ynov/Cours/b2-network/TP-4-Sécu$ ip a
3: wlp0s20f3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:a5:54:c6:91:d4 //MAC  brd ff:ff:ff:ff:ff:ff
    inet 10.33.72.147/20 //IP brd 10.33.79.255 scope global dynamic noprefixroute wlp0s20f3
       valid_lft 77633sec preferred_lft 77633sec
    inet6 fe80::1b21:d72d:2afb:5b58/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever


nanouche@Ubuntu:~$ arp -a
? (10.33.79.22) à 00:41:0e:2b:91:5d [ether] sur wlp0s20f3 // Machine de PC2
_gateway (10.33.79.254) à 7c:5a:1c:d3:d8:76 [ether] sur wlp0s20f3

nanouche@Ubuntu:~$ sudo ip neigh flush all

nanouche@Ubuntu:~$ sudo python3 arp-poisoning.py
```
#### PC Mathéo :
```
matheo@matheo-Modern-14-C7M:~$ ip n s
10.33.79.254 dev wlp1s0 lladdr 7c:5a:1c:d3:d8:76 REACHABLE
10.13.33.37 dev wlp1s0 lladdr de:ad:be:ef:ca:fe STALE
```