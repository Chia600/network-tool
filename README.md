# Network Analyser Java

Un analyseur réseau Java façon Wireshark, combinant scan de ports et capture de paquets, utilisable en conteneur Docker.

## Fonctionnalités
- **Scan de ports TCP** : Affiche l’état (ouvert/fermé), le protocole associé (HTTP, DNS, FTP, etc.) et la bannière du service si disponible.
- **Capture de paquets** : Affiche les paquets réseau en détail (Ethernet, IP, TCP/UDP, ports, adresses, protocole, timestamp, taille, contenu brut en hexadécimal + ASCII).
- **Détection de protocoles applicatifs** : Identification automatique des protocoles courants par port et par payload (HTTP, DNS, FTP, etc.).
- **Affichage lisible** : Formatage façon Wireshark, sections claires, indentation, hexadécimal + ASCII.
- **Docker ready** : Build et exécution dans un conteneur Docker avec Maven et Java 21.

## Utilisation

### 1. Build & Run
```sh
./build_and_run.sh
```
Le script build l’image Docker, lance le conteneur et exécute l’analyseur.

### 2. Fonctions principales
- **Lister les interfaces réseau**
- **Scanner les ports** (modifiable dans le main)
- **Capturer des paquets** (modifiable dans le main)

## Exemple de sortie
```
=== Network Interfaces ===
--- Interfaces réseau détectées ---
Interface : wlp2s0
  Nom affiché : wlp2s0
  Adresse : 10.82.8.21
=== Port Scan ===
Port    80 : FERMÉ  | Protocole : HTTP
Port   443 : FERMÉ  | Protocole : HTTPS
...
=== Packet Capture ===
Paquet #1
Horodatage : ...
Taille : ... octets
[Ethernet]
  Source MAC : ...
  Destination MAC : ...
[IPv4]
  Source IP : ...
  Destination IP : ...
  Protocole : ...
[TCP]
  Port source : ... | Port destination : ... | Protocole applicatif : ...
[Données brutes]
0000  ...  ...
```

## Personnalisation
- Modifiez la plage de ports ou l’interface réseau dans le `main`.
- Ajoutez des protocoles dans la méthode `detectProtocol`.

## Dépendances
- Java 21
- Maven
- Pcap4J
- Docker
- libpcap-dev (pour la capture réseau)

## Auteur
Projet réalisé par Chia600 pour l’apprentissage et l’audit réseau.

---
Ce projet est open-source et améliorable : n’hésitez pas à proposer des ajouts (détection de nouveaux protocoles, analyse OS, etc.) !
