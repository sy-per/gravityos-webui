# GravityOS WebUI

Interface web pour GravityOS — NAS System basé sur Debian 12.

## Structure

```
gravityos-webui/
├── server.js          ← Backend Express + WebSocket + API
├── package.json
└── web/
    ├── index.html     ← SPA React (dashboard, connexion, wizard 1er démarrage —
    │                     tout géré côté client selon /api/auth/status)
    ├── assets/        ← Bundle JS/CSS généré par `npm run build` (frontend/)
    ├── install.html   ← Assistant installation sur disque (Live CD, hors SPA)
    └── gravity-logo.png, gravity-icon.png, favicon.svg, icons.svg
```

La connexion et l'assistant de premier démarrage ne sont plus des pages
HTML séparées (`login.html`/`wizard.html`, supprimées) : la SPA React
gère tout elle-même selon la réponse de `GET /api/auth/status`.
`install.html` reste une page à part exprès — c'est l'installeur disque
du Live CD, exécuté avant même que GravityOS (et sa SPA) ne soit installé.

Le contenu de `web/` est un **build de production**, pas du code source
à modifier directement — il est généré depuis le frontend React source
(dépôt de développement séparé) via `npm run build`, puis copié ici.

## Installation manuelle

```bash
cd /opt/gravity
git clone https://github.com/sy-per/gravityos-webui.git .
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
