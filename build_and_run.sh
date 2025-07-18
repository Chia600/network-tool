#!/bin/bash

# Construire l'image Docker
echo "Construction de l'image Docker..."
docker build -t network-analyzer .

# Exécuter le conteneur avec les privilèges réseau nécessaires
echo "Lancement du conteneur..."
docker run --rm --network host network-analyzer