import sys
from pathlib import Path
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))
import Server.security as security
import sqlite3
from DB import database


DB_FILE = "Database/secbank.db"

def seed_database():
    test_users = [
        ("Marcos", "marcosSecurePass2026"),
        ("Pedro", "PedroBlankPass456"),
        ("Cristina", "crisSSII26-27"),
        ("Carlos", "carlosVault789")
    ]

    conn = database.get_connection()
    c = conn.cursor()
    print("[*] Insertando usuarios de prueba en la base de datos...")

    for username, password in test_users:
        salt, pwd_hash = security.hash_password(password)
        try:
            c.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                      (username, pwd_hash, salt))
            print(f"[+] Usuario '{username}' registrado exitosamente.")
        except sqlite3.IntegrityError:
            print(f"[!] Usuario '{username}' ya existe en la base de datos.")

    conn.commit()
    conn.close()
    print("[*] Base de datos lista para pruebas.")


if __name__ == "__main__":
    seed_database()