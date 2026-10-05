from multiprocessing.managers import Token
import sqlite3
from pathlib import Path

# ==========================================
# CONFIGURACIÓN DE RUTAS
# ==========================================
# Se utiliza pathlib para obtener la ruta absoluta independientemente de 
# desde dónde se ejecute el script para evitar errores de "archivo no encontrado".
BASE_DIR = Path(__file__).resolve().parent.parent
DB_FILE = BASE_DIR / "DB/secbank.db"



def init_db():
    """
    Inicializa la base de datos de SecBank.
    Crea las tablas necesarias (users, nonces, transactions) si no existen previamente.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # ------------------------------------------
    # TABLA DE CREDENCIALES Y USUARIOS
    # ------------------------------------------
    # Almacena la información de los usuarios aplicando buenas prácticas de seguridad:
    # contraseñas hasheadas con salt y control de intentos de inicio de sesión.
    c.execute('''CREATE TABLE IF NOT EXISTS users(
                    userId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash BLOB,                       -- Hash de la contraseña (nunca en texto plano)
                    salt TEXT,                                -- Cadena aleatoria para defenderse contra ataques de diccionario/Rainbow Tables
                    failed_attempts INTEGER DEFAULT 0,        -- Contador para bloquear la cuenta y evitar ataques de fuerza bruta
                    lockout_until INTEGER,                    -- NUEVO: Marca de tiempo hasta cuándo está bloqueada la cuenta
                    session_token BLOB                        -- Token de sesión actual del usuario autenticado
                )''')
    
    # ------------------------------------------
    # TABLA DE NONCES (Number used ONCE)
    # ------------------------------------------
    # Utilizada para prevenir ataques de repetición (Replay Attacks).
    # Guarda identificadores únicos de peticiones recientes para asegurar 
    # que una misma petición criptográfica no se procese dos veces.
    c.execute('''CREATE TABLE IF NOT EXISTS nonces(
                    nonce TEXT primary key,                    -- Cadena única de un solo uso
                    timestamp INTEGER,                         -- Marca de tiempo de creación del nonce para caducidad
                    UNIQUE(nonce, timestamp))''')

    # ------------------------------------------
    # TABLA DE TRANSACCIONES
    # ------------------------------------------
    # Registro inmutable de los movimientos de dinero.
    c.execute('''CREATE TABLE IF NOT EXISTS transactions(
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,      
                    txId TEXT UNIQUE,                                   -- Identificador único de la transacción (ej. UUID)
                    origin_account TEXT,                                -- Cuenta emisora
                    destination_account TEXT,                           -- Cuenta receptora
                    amount REAL,                                        -- Cantidad de dinero transferida
                    currency TEXT                                       -- Moneda de la transacción (ej. EUR, USD)
                )''')
    # Guarda los cambios y cierra la conexión
    conn.commit()
    conn.close()

def get_connection():
    """
    Establece y devuelve una conexión a la base de datos principal.
    Debe ser utilizada por otros módulos que requieran interactuar con la BD.
    
    Returns:
        sqlite3.Connection: Objeto de conexión a la base de datos.
    """
    return sqlite3.connect(DB_FILE)

if __name__ == "__main__":
    # Bloque de ejecución principal: solo se ejecuta si este script se llama directamente.
    init_db()
    print("Base de datos secbank.db inicializada con soporte para sesiones.")