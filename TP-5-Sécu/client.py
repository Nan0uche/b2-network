import socket
import sys
import logging

# On définit la destination de la connexion
host = '10.33.72.233'  # Remplacez cette IP par la bonne IP du serveur
port = 13337        # Remplacez ce port par le bon port choisi par le serveur

class CustomFormatter(logging.Formatter):
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    
    FORMATS = {
        logging.ERROR: red + "%(levelname)s %(asctime)s %(message)s" + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno) 
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record) 

try:
    # Create a custom logger
    logger = logging.getLogger("bs_server")
    logger.setLevel(logging.DEBUG)

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler('/var/log/bs_client/bs_client.log')
    c_handler.setLevel(logging.ERROR)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add it to handlers
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    c_handler.setFormatter(CustomFormatter())
    f_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)
except Exception as e:
    print(f"Failed to configure logging: {e}")

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    while True:
        logger.info("Connexion réussie à %s:%s", host, port)
        s.send("Ok".encode())
        data = s.recv(1024)
        logger.info(f"Réponse reçue du serveur {host} : {repr(data)}")

        userMessage = input("Message a envoyé : ")
        s.send(userMessage.encode())

        data = s.recv(1024)
        print(f"Réponse reçue du serveur {host} : {repr(data.decode())}")
        logger.info(f"Réponse reçue du serveur {host} : {repr(data)}")

except socket.error as e:
    logger.error("Impossible de se connecter au serveur %s sur le port %s", host, port)
    s.close()
    sys.exit(1)