import sqlite3
import secrets
import hashlib

ITERATIONS = 100000

def hash_password(password: str, salt: bytes) -> str:
    """Deriva la contraseña usando PBKDF2-HMAC-SHA256."""
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)
    return key.hex()

def pre_registrar_usuarios():
    conn = sqlite3.connect('secbank.db')
    c = conn.cursor()

    # Tres usuarios listos para las pruebas
    usuarios_prueba = [
        ("cliente1", "contraseña"),
        ("cliente2", "12345"),
        ("cliente3", "SSII")
    ]

    for username, password in usuarios_prueba:
        # Generar salt único de 16 bytes y derivar la contraseña
        salt = secrets.token_bytes(16)
        password_hash = hash_password(password, salt)
        
        try:
            c.execute("INSERT INTO users (username, password_hash, salt, failed_attempts) VALUES (?, ?, ?, ?)",
                      (username, password_hash, salt.hex(), 0))
            print(f"Usuario '{username}' registrado correctamente.")
        except sqlite3.IntegrityError:
            print(f"El usuario '{username}' ya existía en la base de datos.")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    pre_registrar_usuarios()