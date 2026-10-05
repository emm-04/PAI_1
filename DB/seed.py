import sys
from pathlib import Path

# ==========================================
# CONFIGURACIÓN DE RUTAS E IMPORTACIONES
# ==========================================
# Para que Python pueda encontrar e importar módulos que están en carpetas superiores o hermanas
# (como 'Server' y 'DB'), obtenemos la ruta del directorio padre y la añadimos dinámicamente
# al path del sistema durante la ejecución del script.
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))

import Server.security as security
import sqlite3
from DB import database


DB_FILE = "Database/secbank.db"

def seed_database():
    """
    Puebla (seed) la base de datos con información inicial para pruebas.
    Toma una lista de usuarios con contraseñas en texto plano, las procesa de 
    forma segura y las inserta en la base de datos.
    """

    # Lista de usuarios de prueba (Username, Password en texto plano).
    # Útil para tener un entorno funcional sin tener que registrar usuarios a mano cada vez.
    test_users = [
        ("Marcos", "Secur3Bank!2026"),
        ("Pedro", "BlankP@ssword456"),
        ("Cristina", "T3st_SSII_2026%"),
        ("Carlos", "V@ultAccess789*")
    ]

    # Obtenemos la conexión utilizando el módulo 'database' previamente configurado
    conn = database.get_connection()
    c = conn.cursor()
    print("[*] Insertando usuarios de prueba en la base de datos...")

    # Iteramos sobre cada usuario de prueba para procesarlo e insertarlo
    for username, password in test_users:
        # 1. PROCESAMIENTO SEGURO: 
        # Delegamos la generación del hash y el salt al módulo de seguridad.
        # NUNCA se interactúa con la BD usando la contraseña en texto plano.
        salt, pwd_hash = security.hash_password(password)
        try:
            # 2. INSERCIÓN:
            # Utilizamos consultas parametrizadas (?, ?, ?) para evitar inyecciones SQL.
            c.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                      (username, pwd_hash, salt))
            print(f"[+] Usuario '{username}' registrado exitosamente.")
        except sqlite3.IntegrityError:
            # 3. MANEJO DE COLISIONES:
            # Si el script se ejecuta más de una vez, SQLite lanzará un IntegrityError 
            # porque la columna 'username' está marcada como UNIQUE. 
            # Lo capturamos para que el script no se rompa.
            print(f"[!] Usuario '{username}' ya existe en la base de datos.")

    # Guardamos los cambios de las inserciones exitosas y cerramos la conexión
    conn.commit()
    conn.close()
    print("[*] Base de datos lista para pruebas.")


if __name__ == "__main__":
    # Bloque de ejecución principal: solo ejecuta la función si el script 
    # se lanza directamente desde la terminal.
    seed_database()