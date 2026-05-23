# GravityOS WebUI

Interface web pour GravityOS — NAS System basé sur Debian 12.

## Structure

```
gravityos-webui/
├── server.js          ← Backend Express + WebSocket + API
├── package.json
└── web/
    ├── index.html     ← Dashboard principal
    ├── login.html     ← Page de connexion + wizard 1er démarrage
    ├── wizard.html    ← Configuration initiale (hostname, user...)
    ├── install.html   ← Assistant installation sur disque
    └── gravity-logo.png
```

## Installation manuelle

```bash
cd /opt/gravity
git clone https://github.com/TON_USERNAME/gravityos-webui.git .
npm install --ignore-scripts --omit=optional
systemctl restart gravity-webui
```

## Mise à jour via WebUI

Dans GravityOS → Mises à jour → GravityOS WebUI → Vérifier → Mettre à jour

## Mise à jour manuelle

```bash
cd /opt/gravity
git pull origin main
npm install --ignore-scripts --omit=optional
systemctl restart gravity-webui
```

## Ports

| Service | Port |
|---------|------|
| WebUI   | 4000 (via Nginx:80) |
| Terminal | 4200 (shellinabox) |
