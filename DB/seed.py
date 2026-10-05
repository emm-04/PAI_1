import sqlite3
import sys
import logging
from pathlib import Path


# ==========================================
# CONFIGURACIÓN DE RUTAS E IMPORTACIONES
# ==========================================
# Ajustamos las rutas para poder importar los módulos del proyecto
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))

import DB.database as database
import Server.security as security


# ==========================================
# CONFIGURACIÓN DE AUDITORÍA (LOGGING)
# ==========================================
# Configurar el mismo archivo de log que el servidor
logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    handlers = [
        logging.FileHandler("server_audit.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SecBank-Seed")

def run_seed():
    """
    Puebla la base de datos con usuarios de prueba (semilla).
    Utiliza el módulo de seguridad para generar los hashes y salts
    antes de la inserción directa en SQLite.
    """
    logger.info("Iniciando volcado de datos semilla (Seed)...")
    
    # Lista de usuarios de prueba con contraseñas que cumplen la nueva política
    test_users = [
        ("Marcos", "Secur3Bank!2026"),
        ("Pedro", "BlankP@ssword456"),
        ("Cristina", "T3st_SSII_2026%"),
        ("Carlos", "V@ultAccess789*")
    ]

    # Obtenemos la conexión a la base de datos usando nuestro módulo
    conn = database.get_connection()
    c = conn.cursor()

    for username, password in test_users:
        # 1. Generamos el hash criptográfico y el salt
        salt, key = security.hash_password(password)
        
        # 2. Insertamos en la base de datos
        try:
            c.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                      (username, key, salt))
            conn.commit()
            logger.info(f"Usuario semilla registrado directamente en BD: '{username}'")
        except sqlite3.IntegrityError:
            logger.warning(f"El usuario semilla '{username}' ya existe en la base de datos. Saltando...")

    conn.close()
    logger.info("Proceso de inicialización de usuarios finalizado.")

if __name__ == "__main__":
    run_seed()