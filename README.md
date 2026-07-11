# Analyseur de code - Guide d'installation

## 1. Copier le projet sur ta VM

```bash
scp -r ./analyseur user@IP_VM:/opt/analyseur
# ou git clone si tu utilises un dépôt
```

## 2. Installer les dépendances système

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y cppcheck clang clang-tidy flawfinder
sudo apt install -y nginx wkhtmltopdf
```

## 3. Préparer le projet

```bash
cd /opt/analyseur
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir -p data/cve reports
```

## 4. Démarrage rapide (développement)

```bash
cd /opt/analyseur
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

L'API est accessible sur : http://IP_VM:8000
Documentation auto : http://IP_VM:8000/docs

## 5. Démarrage en production (systemd + Nginx)

```bash
# Installer le service systemd
sudo cp analyseur.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable analyseur
sudo systemctl start analyseur

# Configurer Nginx
sudo cp nginx_analyseur.conf /etc/nginx/sites-available/analyseur
sudo ln -s /etc/nginx/sites-available/analyseur /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

L'API sera accessible sur : http://IP_VM/ (port 80)

## 6. Ajouter la base CVE ANSSI

Dépose tes fichiers JSON dans le dossier `data/cve/`.

### Formats supportés
- NVD JSON 2.0 (fichiers nvdcve-2.0-*.json)
- NVD JSON 1.1 (fichiers nvdcve-1.1-*.json)
- Format CERT-FR liste JSON simple

### Téléchargement NVD (gratuit)
```bash
cd data/cve
# Télécharger par année (exemple 2023 et 2024)
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz
gunzip *.gz
```

## 7. Vérification

```bash
# Tester l'API
curl http://localhost:8000/api/health

# Test d'analyse Python
curl -X POST http://localhost:8000/api/analyse/ \
  -H "Content-Type: application/json" \
  -d '{"code": "import pickle\npickle.loads(data)", "langage": "python", "mode": "classique"}'

# Test d'analyse C
curl -X POST http://localhost:8000/api/analyse/ \
  -H "Content-Type: application/json" \
  -d '{"code": "#include <stdio.h>\nint main(){char buf[10];gets(buf);}", "langage": "c", "mode": "classique"}'
```

## Structure des fichiers

```
/opt/analyseur/
├── app/
│   ├── main.py              # Point d'entrée FastAPI
│   ├── database.py          # SQLite async
│   ├── engines/
│   │   ├── moteur_c.py      # Analyse C (cppcheck + flawfinder)
│   │   └── moteur_python.py # Analyse Python (bandit + pyflakes)
│   ├── models/
│   │   └── schemas.py       # Modèles Pydantic
│   ├── routers/
│   │   ├── analyse.py       # POST /api/analyse/
│   │   └── rapports.py      # GET/DELETE /api/rapports/
│   └── services/
│       ├── cve_service.py   # Corrélation CVE ANSSI
│       └── rapport_service.py # Génération PDF/HTML
├── data/
│   ├── analyseur.db         # Base SQLite
│   └── cve/                 # Vos fichiers JSON CVE
├── reports/                 # Rapports générés
├── requirements.txt
├── start.sh
├── analyseur.service        # Systemd
└── nginx_analyseur.conf     # Nginx
```

## Endpoints API

| Méthode | URL | Description |
|---------|-----|-------------|
| GET | /api/health | État de l'API |
| POST | /api/analyse/ | Lancer une analyse |
| GET | /api/rapports/ | Lister les rapports |
| GET | /api/rapports/{id} | Détail d'un rapport |
| GET | /api/rapports/{id}/json | Télécharger JSON |
| GET | /api/rapports/{id}/pdf | Télécharger PDF |
| DELETE | /api/rapports/{id} | Supprimer un rapport |
