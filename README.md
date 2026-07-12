# CodeShield — Analyseur de sécurité de code

CodeShield est un outil d'analyse statique de code source développé en M2 cybersécurité.
Il détecte les vulnérabilités dans le code C et Python, les classe par niveau de gravité
et génère des rapports exportables en PDF et JSON.

## Fonctionnalités

- Analyse statique C (cppcheck + flawfinder) et Python (bandit + pyflakes)
- Score de sécurité sur 100 basé sur les sévérités CVSS v3.1
- Mode avancé avec corrélation CVE depuis la base ANSSI (2016-2026)
- Export des rapports en PDF et JSON
- Historique des analyses par navigateur
- Import de fichiers .c et .py directement dans l'interface
- Interface web accessible depuis le réseau local via Nginx

## Prérequis système

```bash
sudo apt install -y python3 python3-venv cppcheck flawfinder nginx
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfontconfig1
pip install bandit pyflakes
```

## Installation

```bash
# Cloner le projet
git clone https://github.com/mysticslol/PA.git
cd PA

# Créer l'environnement virtuel et installer les dépendances Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Créer les dossiers nécessaires
mkdir -p data/cve reports
```

## Ajouter la base CVE

Déposez vos fichiers JSON au format CVElist V5 dans le dossier `data/cve/`.
La structure attendue est : `data/cve/ANNEE/Xxxx/CVE-ANNEE-XXXX.json`

Les fichiers sont chargés automatiquement en mémoire au premier lancement du serveur.

## Lancement

```bash
cd PA
source venv/bin/activate
venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

L'API est accessible sur `http://localhost:8000`
La documentation automatique est disponible sur `http://localhost:8000/docs`

## Configuration Nginx (accès réseau local)

```bash
sudo cp nginx_analyseur.conf /etc/nginx/sites-available/codeshield
sudo ln -s /etc/nginx/sites-available/codeshield /etc/nginx/sites-enabled/
sudo mkdir -p /var/www/codeshield
sudo cp index.html /var/www/codeshield/
sudo nginx -t && sudo systemctl restart nginx
```

Le site sera alors accessible depuis n'importe quel PC du réseau local via l'IP de la VM.

## Structure du projet

```
PA/
├── index.html                  — Interface web (frontend)
├── nginx_analyseur.conf        — Configuration Nginx
├── analyseur.service           — Service systemd
├── requirements.txt            — Dépendances Python
│
├── app/
│   ├── main.py                 — Point d'entrée FastAPI
│   ├── database.py             — Base de données SQLite
│   ├── models/schemas.py       — Structures de données (Pydantic)
│   ├── routers/
│   │   ├── analyse.py          — Route POST /api/analyse/
│   │   └── rapports.py         — Routes GET/DELETE /api/rapports/
│   ├── engines/
│   │   ├── moteur_c.py         — Analyse C (cppcheck + flawfinder)
│   │   └── moteur_python.py    — Analyse Python (bandit + pyflakes)
│   └── services/
│       ├── cve_service.py      — Corrélation CVE ANSSI
│       ├── rapport_service.py  — Génération PDF/HTML/JSON
│       └── ia_service.py       — Infrastructure IA (désactivée)
│
├── data/
│   ├── analyseur.db            — Base SQLite (historique)
│   └── cve/                    — Fichiers CVE ANSSI (2016-2026)
│
└── reports/                    — Rapports générés
```

## Endpoints API

| Méthode | URL | Description |
|---------|-----|-------------|
| GET | /api/health | État du serveur |
| POST | /api/analyse/ | Lancer une analyse |
| GET | /api/rapports/ | Lister l'historique |
| GET | /api/rapports/{id} | Détail d'un rapport |
| GET | /api/rapports/{id}/json | Télécharger en JSON |
| GET | /api/rapports/{id}/pdf | Télécharger en PDF |
| DELETE | /api/rapports/{id} | Supprimer un rapport |

## Système de scoring

Le score de sécurité est calculé en soustrayant des points selon la sévérité
de chaque vulnérabilité détectée, conformément au standard CVSS v3.1 :

| Sévérité | Points retirés | Seuil CVSS |
|----------|---------------|------------|
| Critique | -25 | 9.0 - 10.0 |
| Haute | -10 | 7.0 - 8.9 |
| Moyenne | -4 | 4.0 - 6.9 |
| Basse | -1 | 0.1 - 3.9 |
