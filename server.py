import sqlite3
import hashlib
import secrets
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
import uvicorn

import time
import hmac
import json

# --- CONFIGURACIÓN DE SEGURIDAD (RS1) ---
ITERATIONS = 100000
MAX_FAILED_ATTEMPTS = 3

def hash_password(password: str, salt: bytes) -> str:
    """Deriva la contraseña usando PBKDF2-HMAC-SHA256."""
    key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        ITERATIONS
    )
    return key.hex()

def get_db_connection():
    conn = sqlite3.connect('secbank.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- INICIALIZACIÓN DE LA API ---
app = FastAPI()

class UserCredentials(BaseModel):
    username: str
    password: str

# --- ENDPOINTS DE GESTIÓN DE USUARIOS (Paso 2) ---

@app.post("/api/v1/register")
async def register_user(creds: UserCredentials):
    conn = get_db_connection()
    c = conn.cursor()
    
    # Comprobar si el usuario ya existe para evitar duplicados[cite: 1]
    c.execute("SELECT id FROM users WHERE username = ?", (creds.username,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="El usuario ya existe.")
    
    # Generar un salt aleatorio único de 16 bytes[cite: 1]
    salt = secrets.token_bytes(16)
    
    # Derivar la contraseña[cite: 1]
    password_hash = hash_password(creds.password, salt)
    
    # Almacenar en base de datos
    c.execute("INSERT INTO users (username, password_hash, salt, failed_attempts) VALUES (?, ?, ?, ?)",
              (creds.username, password_hash, salt.hex(), 0))
    conn.commit()
    conn.close()
    
    return {"message": "Usuario registrado correctamente."}

@app.post("/api/v1/login")
async def login_user(creds: UserCredentials):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT * FROM users WHERE username = ?", (creds.username,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")
    
    # Verificar bloqueo por fuerza bruta[cite: 1]
    if user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
        conn.close()
        raise HTTPException(status_code=403, detail="Cuenta bloqueada por múltiples intentos fallidos.")
    
    # Recuperar el salt y recalcular el hash de la contraseña ingresada
    salt = bytes.fromhex(user['salt'])
    input_hash = hash_password(creds.password, salt)
    
    # COMPARACIÓN EN TIEMPO CONSTANTE para evitar Timing Attacks (RS4)[cite: 1]
    if secrets.compare_digest(input_hash, user['password_hash']):
        # Login exitoso: reiniciar contador de intentos
        c.execute("UPDATE users SET failed_attempts = 0 WHERE username = ?", (creds.username,))
        session_token = secrets.token_urlsafe(32)
        conn.commit()
        conn.close()
        return {"message": "Login exitoso", "session_token": session_token}
    else:
        # Login fallido: incrementar contador[cite: 1]
        c.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?", (creds.username,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")

# --- ENDPOINT DE TRANSACCIONES (Base del Paso 1, que completaremos en el Paso 3) ---

# Clave compartida para simular la sesión (mínimo 256 bits según RS2)
SHARED_SECRET = b"esta_es_una_clave_compartida_muy_segura_256b"
WINDOW_SECONDS = 300  # Ventana de 5 minutos para el Timestamp

@app.post("/api/v1/transfer")
async def process_transfer(
    request: Request,
    x_signature: str = Header(None),
    x_nonce: str = Header(None),
    x_timestamp: int = Header(None)
):
    # 1. Validar que los parámetros de seguridad están presentes
    if not x_signature or not x_nonce or not x_timestamp:
        raise HTTPException(status_code=400, detail="Faltan cabeceras de seguridad.")

    # 2. Protección contra Replay: Validar ventana de tiempo (RS3)
    current_time = int(time.time())
    if abs(current_time - x_timestamp) > WINDOW_SECONDS:
        raise HTTPException(status_code=403, detail="Mensaje expirado (Posible Replay).")

    # 3. Protección contra Replay: Validar Nonce en Base de Datos (RS3)[cite: 1]
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT nonce FROM nonces WHERE nonce = ?", (x_nonce,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Nonce repetido (Ataque Replay bloqueado).")

    # 4. Leer el cuerpo de la petición EXACTAMENTE como llegó
    body_bytes = await request.body()

    # 5. Calcular el HMAC esperado (RS2)[cite: 1]
    expected_mac = hmac.new(SHARED_SECRET, body_bytes, hashlib.sha256).hexdigest()

    # 6. Mitigación Timing Attacks: Comparación en tiempo constante (RS4)[cite: 1]
    if not secrets.compare_digest(expected_mac, x_signature):
        conn.close()
        raise HTTPException(status_code=401, detail="Firma HMAC inválida (Mensaje alterado).")

    # 7. Registrar el Nonce para "quemarlo" y que no se vuelva a usar[cite: 1]
    c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (x_nonce, current_time))
    conn.commit()
    conn.close()

    payload = json.loads(body_bytes)
    return {"status": "success", "message": f"Transferencia de {payload.get('amount')} EUR validada de forma segura."}

# --- ARRANQUE DEL SERVIDOR ---
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)