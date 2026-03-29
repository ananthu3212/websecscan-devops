import os
from dotenv import load_dotenv

# 🔹 Lädt Variablen aus der .env-Datei
load_dotenv()

class Settings:
    # 💾 Verbindung zur PostgreSQL-Datenbank (liest aus .env)
    DB_URL: str = os.getenv(
        "DB_URL",
        "postgresql+psycopg2://websecuser:websecpass@websecscan-db:5432/websecscan"
    )

settings = Settings()
