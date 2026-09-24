import sqlite3
import hashlib
import secrets
import time
import hmac
import json
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
import uvicorn

# --- CONFIGURACIÓN DE SEGURIDAD ---
ITERATIONS = 100000
MAX_FAILED_ATTEMPTS = 3
SHARED_SECRET = bytes.fromhex("9597a9db133b65dda1588cb88286a646b7876af37451fa62f368c2548bfc162d")
WINDOW_SECONDS = 300 

def hash_password(password: str, salt: bytes) -> str:
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)
    return key.hex()

def get_db_connection():
    conn = sqlite3.connect('secbank.db')
    conn.row_factory = sqlite3.Row
    return conn

app = FastAPI()

class UserCredentials(BaseModel):
    username: str
    password: str

# --- ENDPOINTS DE GESTIÓN DE USUARIOS ---

@app.post("/api/v1/register")
async def register_user(creds: UserCredentials):
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT id FROM users WHERE username = ?", (creds.username,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="El usuario ya existe.")
    
    salt = secrets.token_bytes(16)
    password_hash = hash_password(creds.password, salt)
    
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
    
    if user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
        conn.close()
        raise HTTPException(status_code=403, detail="Cuenta bloqueada por múltiples intentos fallidos.")
    
    salt = bytes.fromhex(user['salt'])
    input_hash = hash_password(creds.password, salt)
    
    if secrets.compare_digest(input_hash, user['password_hash']):
        # Login exitoso: reiniciar contador y guardar token de sesión
        session_token = secrets.token_urlsafe(32)
        c.execute("UPDATE users SET failed_attempts = 0, session_token = ? WHERE username = ?", 
                  (session_token, creds.username))
        conn.commit()
        conn.close()
        return {"message": "Login exitoso", "session_token": session_token}
    else:
        c.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?", (creds.username,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")

@app.post("/api/v1/logout")
async def logout_user(x_session_token: str = Header(None)):
    if not x_session_token:
        raise HTTPException(status_code=400, detail="Token de sesión no proporcionado.")
        
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("UPDATE users SET session_token = NULL WHERE session_token = ?", (x_session_token,))
    
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=401, detail="Sesión inválida o ya cerrada.")
        
    conn.commit()
    conn.close()
    return {"message": "Sesión cerrada correctamente (Logout)."}

# --- ENDPOINT DE TRANSACCIONES ---

@app.post("/api/v1/transfer")
async def process_transfer(
    request: Request,
    x_signature: str = Header(None),
    x_nonce: str = Header(None),
    x_timestamp: int = Header(None)
):
    if not x_signature or not x_nonce or not x_timestamp:
        raise HTTPException(status_code=400, detail="Faltan cabeceras de seguridad.")

    current_time = int(time.time())
    if abs(current_time - x_timestamp) > WINDOW_SECONDS:
        raise HTTPException(status_code=403, detail="Mensaje expirado (Posible Replay).")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT nonce FROM nonces WHERE nonce = ?", (x_nonce,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Nonce repetido (Ataque Replay bloqueado).")

    body_bytes = await request.body()
    expected_mac = hmac.new(SHARED_SECRET, body_bytes, hashlib.sha256).hexdigest()

    if not secrets.compare_digest(expected_mac, x_signature):
        conn.close()
        raise HTTPException(status_code=401, detail="Firma HMAC inválida.")

    c.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (x_nonce, current_time))
    conn.commit()
    conn.close()

    payload = json.loads(body_bytes)
    
    # NUEVO: Registrar la transacción tras comprobar su integridad[cite: 1]
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''INSERT INTO transactions 
                 (tx_id, origin_account, destination_account, amount, currency) 
                 VALUES (?, ?, ?, ?, ?)''', 
              (payload['tx_id'], payload['origin_account'], payload['destination_account'], 
               payload['amount'], payload['currency']))
    conn.commit()
    conn.close()

    return {"status": "success", "message": f"Transferencia validada y registrada de forma segura."}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)