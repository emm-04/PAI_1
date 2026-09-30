import sqlite3
from pathlib import Path

# Obtiene la ruta absoluta de la carpeta raíz del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent
DB_FILE = BASE_DIR / "DB/secbank.db"



def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    #Tabla de credenciales
    c.execute('''CREATE TABLE IF NOT EXISTS users(
                    userId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash BLOB,
                    salt TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until REAL DEFAULT NULL,
                    session_token BLOB)''')

    #Tabla de nonces
    c.execute('''CREATE TABLE IF NOT EXISTS nonces(
                    nonce TEXT primary key,
                    timestamp INTEGER,
                    UNIQUE(nonce, timestamp))''')

    #Tabla de transacciones
    c.execute('''CREATE TABLE IF NOT EXISTS transactions(
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    txId TEXT UNIQUE,
                    origin_account TEXT,
                    destination_account TEXT,
                    amount REAL,
                    currency TEXT)''')

    conn.commit()
    conn.close()

def get_connection():
     return sqlite3.connect(DB_FILE)

if __name__ == "__main__":
    init_db()
    print("Base de datos secbank.db inicializada con soporte para sesiones.")

