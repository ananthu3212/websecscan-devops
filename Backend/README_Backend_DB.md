

# 📘 WebSecScan – README

## 🚀 Übersicht

Dieses Projekt ist eine **Web Security Scanning Plattform**, die mehrere Tools integriert:

* **Nmap** → Port- und Service-Scanning
* **WhatWeb** → Fingerprinting von Webtechnologien
* **Nikto** → Webserver-Schwachstellenanalyse
* **OWASP ZAP** → Automatisierter Vulnerability-Scan

Die Ergebnisse werden in einer **PostgreSQL-Datenbank** gespeichert.
Das Projekt basiert auf **Flask (Backend)**, **Docker Compose** und **Postgres**.

---

## 📂 Projektstruktur

```
.
├── Backend/                 # Backend-Code + Dockerfile
│   ├── app.py
│   ├── crud.py
│   ├── db.py
│   ├── models.py
│   ├── requirements.txt
│   └── Dockerfile           # Backend Dockerfile
├── docker-compose.yml       # Orchestrierung aller Services
├── requirements.txt         # Root requirements (verweist auf Backend/requirements.txt)
├── .env                     # Umgebungsvariablen
└── README.md
```

---

## ⚙️ Voraussetzungen

* **Docker** (>= 20.x)
* **Docker Compose Plugin** (>= v2)
* Optional: **Postman** oder `curl` zum Testen der API

---

## 🔑 Umgebungsvariablen

In der Datei `.env` sind die wichtigsten Einstellungen:

# =========================
# Allgemeine Einstellungen
# =========================
ENV=dev                     # Umgebung: "dev" = Entwicklung, "prod" = Produktion

# =========================
# Datenbank-Konfiguration
# =========================
DB_NAME=websecscan          # Name der PostgreSQL-Datenbank
DB_USER=websecuser          # Benutzername für die Datenbank
DB_PORT=5432                # Standard-Port für PostgreSQL

# --- Falls das Backend innerhalb von Docker läuft ---
DB_HOST=websecscan-db       # Hostname des Datenbankcontainers (siehe docker-compose)
DB_URL=postgresql+psycopg2://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
                            # Vollständige Verbindungs-URL zur Datenbank

# --- Falls das Backend lokal (z. B. unter Windows) läuft ---
# DB_HOST=localhost         # Lokaler Host
# DB_URL=postgresql+psycopg2://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
                            # Alternative URL für lokale Entwicklung ohne Docker

# =========================
# Tools
# =========================
WHATWEB_PATH=C:/WhatWeb/whatweb       # Pfad zu WhatWeb unter Windows
# WHATWEB_PATH=/usr/local/bin/whatweb # Pfad zu WhatWeb im Docker-Container (Linux)

# =========================
# OWASP ZAP Konfiguration
# =========================
ZAP_API_KEY=disabled        # API-Key für ZAP (hier deaktiviert für einfache Nutzung)
ZAP_HOST=zap_scanner        # Hostname des ZAP-Containers (siehe docker-compose)
ZAP_PORT=8080               # Port, auf dem ZAP-API erreichbar ist

## 🐳 Docker-Setup

### 1. Projekt starten (mit Build)

```bash
docker compose up --build
```

👉 Dadurch werden folgende Container gestartet:

* **db** → PostgreSQL
* **zap** → OWASP ZAP Scanner
* **app** → Flask Backend (baut aus `Backend/Dockerfile`)

### 2. Logs live ansehen

```bash
docker compose logs -f app
```

### 3. Container stoppen

```bash
docker compose down
```

---

## 🗄️ Datenbankmigration

Die Tabellen werden über **SQLAlchemy-Models** automatisch erstellt.
Führe folgenden Befehl aus, nachdem die Container laufen:

```bash
docker compose exec app python -c "from Backend.db import engine; from Backend.models import Base; Base.metadata.create_all(bind=engine); print('Tables created')"
```

Tabellen prüfen:

```bash
docker compose exec db psql -U websecuser -d websecscan -c "\dt"
```

---

## 🌐 API-Nutzung

### Health-Check

```bash
curl http://localhost:5001/health
```

Antwort:

```json
{"status":"ok","timestamp":"2025-08-24T10:00:00+00:00"}
```

### Scan starten

```bash
curl -X POST http://localhost:5001/api/scan \
     -H "Content-Type: application/json" \
     -d '{"target":"http://testphp.vulnweb.com"}'
```

Antwort (gekürzt):

```json
{
  "scan_id": 1,
  "target": "http://testphp.vulnweb.com",
  "nmap_data": [...],
  "whatweb_data": {...},
  "nikto_data": {...},
  "zap_data": {...},
  "timestamp": "2025-08-24T10:05:00+00:00"
}
```

---

## ✅ Zusammenfassung

1. `.env` prüfen/anpassen
2. `docker compose up --build`
3. Tabellen erzeugen:

   ```bash
   docker compose exec app python -c "from Backend.db import engine; from Backend.models import Base; Base.metadata.create_all(bind=engine); print('Tables created')"
   ```
4. API via `curl` oder **Postman** testen




