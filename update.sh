#!/bin/bash
# GravityOS WebUI — Script de mise à jour
# Appelé par l'API /api/updates/gravity/start
set -e

INSTALL_DIR="/opt/gravity"
REPO_URL="https://gitlab.com/syper/gravityos-webui.git"
BRANCH="main"

echo "=== GravityOS WebUI Update ==="
echo "Date: $(date)"
echo ""

cd "$INSTALL_DIR"

# Initialiser git si pas encore fait
if [ ! -d ".git" ]; then
  echo "Initialisation du repo git..."
  git init
  git remote add origin "$REPO_URL"
  git fetch origin
  git checkout -b main --track origin/main
else
  echo "Mise à jour depuis $REPO_URL..."
  git fetch origin
  git pull origin "$BRANCH"
fi

echo ""
echo "Mise à jour des dépendances npm..."
npm install --ignore-scripts --omit=optional

echo ""
echo "Redémarrage du service..."
systemctl restart gravity-webui

echo ""
echo "=== Mise à jour terminée ==="
echo "Version: $(git log -1 --format='%h %s' 2>/dev/null || echo 'inconnue')"
