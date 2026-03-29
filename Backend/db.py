from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

# --- Datenbank-URL aus Umgebungsvariablen lesen ---
DB_URL = os.getenv("DB_URL")
if not DB_URL:
    with open("/run/secrets/db_password") as p:
        password = p.read()
    # Fallback (nützlich während der Entwicklung)
    DB_USER = os.getenv("DB_USER", "websecuser")
    DB_PASSWORD = password
    DB_HOST = os.getenv("DB_HOST", "websecscan-db")  # Standard-Host im Docker-Netzwerk
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "websecscan")
    DB_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# --- Engine erstellen (Verbindung zur DB) ---
engine = create_engine(DB_URL, pool_pre_ping=True)

# --- Session-Fabrik erstellen ---
# autocommit=False -> manuelles Commit nötig
# autoflush=False -> Änderungen nicht automatisch vor Flush
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
