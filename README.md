# Serveur de suivi de convoi (accès protégé)

Un seul domaine HTTPS (port 443) : page de contrôle, flux en direct, cartes. Aucun domaine externe : l'entité de contrôle n'a **que ce domaine** à autoriser.

## Fonctionnement
- **Conducteurs** (app) : envoient position et tracé avec la clé `DRIVER_KEY`.
- **Contrôleurs** : ouvrent `https://VOTRE-DOMAINE/` (liste des convois) ou `https://VOTRE-DOMAINE/?c=CODE` (un convoi) avec identifiant et mot de passe (`VIEWER_USERS`).
- Un convoi = un code = un lien = une carte. Deux convois = deux liens.

## Déploiement
### Option A – Render (simple)
1. Mettez ce dossier dans un dépôt GitHub **privé**.
2. Render > New > Blueprint > choisissez le dépôt (`render.yaml`).
3. Saisissez `VIEWER_USERS` (ex. `controle:UnMotDePasseLong`). Relevez `DRIVER_KEY` généré (onglet Environment).
4. Utilisez un plan payant (le gratuit s'endort : positions perdues/retardées).

### Option B – Serveur (VPS) + Caddy
```
npm install --omit=dev
DRIVER_KEY=... VIEWER_USERS=controle:... TRUST_PROXY=1 DATA_DIR=/var/lib/suivi node server.js
```
Caddyfile : `suivi.exemple.fr { reverse_proxy 127.0.0.1:8080 }` (certificat HTTPS automatique). Ou `docker build -t suivi . && docker run -p 8080:8080 --env-file .env suivi`.

## Dans l'app
Convoi > **Adresse du serveur** (`https://VOTRE-DOMAINE`) + **Clé conducteur** (`DRIVER_KEY`). Le lien à transmettre au contrôle est affiché ensuite.

## À transmettre à l'entité de contrôle
- Domaine à autoriser : `VOTRE-DOMAINE` en HTTPS/443 uniquement (WebSocket non utilisé : flux SSE sur HTTPS).
- Identifiant et mot de passe.

## Sécurité
Authentification Basic sur tout (API, flux, tuiles, carte), blocage après 8 échecs (10 min), clé conducteur, limites de débit, validation stricte, CSP, CORS restreint, journal d'accès JSON, positions oubliées après 30 min (sauf `KEEP_HISTORY=1`).
Changer `DRIVER_KEY` coupe aussitôt les anciens téléphones. Un compte par organisation recommandé.
`npm test` lance les 15 tests.
