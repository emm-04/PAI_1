import sqlite3

def init_db():
    conn = sqlite3.connect('secbank.db')
    c = conn.cursor()
    
    # Tabla de usuarios con la nueva columna 'session_token'
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE, 
                  password_hash TEXT, 
                  salt TEXT,
                  failed_attempts INTEGER DEFAULT 0,
                  session_token TEXT)''')
    
    # Tabla de nonces
    c.execute('''CREATE TABLE IF NOT EXISTS nonces
                 (nonce TEXT PRIMARY KEY, 
                  timestamp INTEGER)''')

    # Tabla de transacciones (Nuevo)
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  tx_id TEXT UNIQUE,
                  origin_account TEXT,
                  destination_account TEXT,
                  amount REAL,
                  currency TEXT)''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Base de datos secbank.db inicializada con soporte para sesiones.")