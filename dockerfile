# Utiliser une image Maven avec Java 21
FROM maven:3.9.6-eclipse-temurin-21

# Définir le répertoire de travail
WORKDIR /app

# Installer libpcap pour Pcap4J
RUN apt-get update && apt-get install -y libpcap-dev

# Copier tout le projet Maven dans le conteneur
COPY . /app

# Télécharger les dépendances et compiler le projet
RUN mvn clean package

# Exécuter l'application (adapter le nom de la classe principale si besoin)
CMD ["mvn", "exec:java", "-Dexec.mainClass=com.example.PacketSniffer"]