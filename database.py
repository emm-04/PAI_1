import sqlite3

def init_db():
    conn = sqlite3.connect('secbank.db')
    c = conn.cursor()
    
    # Tabla de usuarios para RS1
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE, 
                  password_hash TEXT, 
                  salt TEXT,
                  failed_attempts INTEGER DEFAULT 0)''')
    
    # Tabla de nonces para RS3 (Protección Replay)
    c.execute('''CREATE TABLE IF NOT EXISTS nonces
                 (nonce TEXT PRIMARY KEY, 
                  timestamp INTEGER)''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Base de datos secbank.db inicializada.")