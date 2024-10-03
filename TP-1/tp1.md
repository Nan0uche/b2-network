## I. Basics

**☀️ Carte réseau WiFi**
```
PS C:\Users\natha> ipconfig /all

Carte réseau sans fil Wi-Fi :

   Adresse physique . . . . . . . . . . . : 00-A5-54-C6-91-D4 // MAC
   Adresse IPv4. . . . . . . . . . . . . .: 10.33.73.4 // IP
   Masque de sous-réseau. . . . . . . . . : 255.255.240.0 = 14 // Masque de sous-réseau
```
**☀️ Déso pas déso**
```
Adresse de Réseau du LAN : 10.33.7
Adresse de Broadcast : 10.33.79.255
Nombre d'Adresses IP Disponibles : 4094
```
**☀️ Hostname**
```
PS C:\Users\natha> hostname
PC-Nathan
```
**☀️ Passerelle du réseau**
```
PS C:\Users\natha> ipconfig /all

Carte réseau sans fil Wi-Fi :

   Passerelle par défaut. . . . . . . . . : 10.33.79.254 //IP

PS C:\Users\natha> arp -a

Interface : 10.33.73.4 --- 0x24
  Adresse Internet      Adresse physique            Type
  10.33.79.254          7c-5a-1c-d3-d8-76 //MAC     dynamique
```
**☀️ Serveur DHCP et DNS**
```
PS C:\Users\natha> ipconfig /all

Carte réseau sans fil Wi-Fi :

   Serveur DHCP . . . . . . . . . . . . . : 10.33.79.254
   Serveurs DNS. . .  . . . . . . . . . . : 8.8.8.8
                                       1.1.1.1
```
**☀️ Table de routage**
```
PS C:\Users\natha> netstat -r
===========================================================================
IPv4 Table de routage
===========================================================================
Itinéraires actifs :
Destination réseau    Masque réseau  Adr. passerelle   Adr. interface Métrique
          0.0.0.0          0.0.0.0     10.33.79.254       10.33.73.4     30
```
## II. Go further

**☀️ Hosts ?**
```
PS C:\Users\natha> ping b2.hello.vous

Envoi d’une requête 'ping' sur b2.hello.vous [1.1.1.1] avec 32 octets de données :
Réponse de 1.1.1.1 : octets=32 temps=17 ms TTL=55
Réponse de 1.1.1.1 : octets=32 temps=21 ms TTL=55
Réponse de 1.1.1.1 : octets=32 temps=34 ms TTL=55
Réponse de 1.1.1.1 : octets=32 temps=48 ms TTL=55

Statistiques Ping pour 1.1.1.1:
    Paquets : envoyés = 4, reçus = 4, perdus = 0 (perte 0%),
Durée approximative des boucles en millisecondes :
    Minimum = 17ms, Maximum = 48ms, Moyenne = 30ms

PS C:\Users\natha> cat C:\Windows\system32\drivers\etc\hosts
#
127.0.0.1 localhost
::1 localhost
1.1.1.1 b2.hello.vous
```
**☀️ Go mater une vidéo youtube et déterminer, pendant qu'elle tourne...**
```
PS C:\Users\natha> netstat -ano

Connexions actives

  Proto  Adresse locale         Adresse distante       État
  TCP    10.33.73.4:63962       142.250.200.238:443    ESTABLISHED     5532
```
**☀️ Requêtes DNS**
```
PS C:\Users\natha> nslookup www.thinkerview.com
Serveur :   dns.google
Address:  8.8.8.8

Réponse ne faisant pas autorité :
Nom :    www.thinkerview.com
Addresses:  2a06:98c1:3120::7
          2a06:98c1:3121::7
          188.114.97.7
          188.114.96.7

PS C:\Users\natha> nslookup 143.90.88.12
Serveur :   dns.google
Address:  8.8.8.8

Nom :    EAOcf-140p12.ppp15.odn.ne.jp
Address:  143.90.88.12
```
**☀️ Hop hop hop**
```
PS C:\Users\natha> tracert www.ynov.com

Détermination de l’itinéraire vers www.ynov.com [172.67.74.226]
avec un maximum de 30 sauts :

  1     2 ms    48 ms     1 ms  10.33.79.254
  2     4 ms     1 ms     2 ms  145.117.7.195.rev.sfr.net [195.7.117.145]
  3    24 ms     2 ms     2 ms  237.195.79.86.rev.sfr.net [86.79.195.237]
  4     3 ms     2 ms     3 ms  196.224.65.86.rev.sfr.net [86.65.224.196]
  5    13 ms    69 ms    11 ms  164.147.6.194.rev.sfr.net [194.6.147.164]
  6     *        *        *     Délai d’attente de la demande dépassé.
  7    38 ms    16 ms    60 ms  162.158.20.240
  8    21 ms    14 ms    15 ms  172.67.74.226
```
**☀️ IP publique**
```
PS C:\Users\natha> curl ifconfig.me

Content           : 195.7.117.146
```
## III. Le requin

**☀️ Capture ARP**
```
PS C:\WINDOWS\system32> ping 10.33.79.254 // Impossible de ping

Envoi d’une requête 'Ping'  10.33.79.254 avec 32 octets de données :
Délai d’attente de la demande dépassé.
Délai d’attente de la demande dépassé.

Statistiques Ping pour 10.33.79.254:
    Paquets : envoyés = 3, reçus = 0, perdus = 3 (perte 100%),
```
**☀️ [Capture DNS](./captures/dns.pcapng)**
```
PS C:\WINDOWS\system32> nslookup pornhub.fr
Serveur :   dns.google
Address:  8.8.8.8

Réponse ne faisant pas autorité :
Nom :    pornhub.fr
Address:  66.254.114.211
```
**☀️ [Capture TCP](./captures/tcp.pcapng)**
```
C:\Users\natha>curl fr.pornhub.com
```