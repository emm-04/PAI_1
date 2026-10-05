from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
import time
import security
import sqlite3
import json
import uvicorn
import sys
import logging
from pathlib import Path

# ==========================================
# CONFIGURACIÓN DE RUTAS E IMPORTACIONES
# ==========================================
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))
import DB.database as database

# ==========================================
# CONFIGURACIÓN DE AUDITORÍA (LOGGING)
# ==========================================
# Se guardarán los registros tanto en la terminal como en el archivo 'server_audit.log'
logging.basicConfig(
    level = logging.INFO,
    format = "%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    handlers = [
        logging.FileHandler("server_audit.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SecBank")

# Inicialización de la aplicación FastAPI
app = FastAPI()

# ==========================================
# MIDDLEWARE DE INTERCEPTACIÓN Y LOGS
# ==========================================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Intercepta todas las peticiones entrantes, mide el tiempo de procesamiento
    y registra los detalles en el log de auditoría.
    """
    start_time = time.time()
    
    # El servidor procesa la petición en su endpoint correspondiente
    response = await call_next(request)
    
    # Calculamos el tiempo de procesamiento
    process_time = (time.time() - start_time) * 1000  # Convertimos a milisegundos
    
    # Registramos: IP Cliente -> MÉTODO /ruta -> Status Code -> Tiempo (ms)
    client_ip = request.client.host if request.client else "Unknown"
    logger.info(f"{client_ip} -> {request.method} {request.url.path} | Status: {response.status_code} | {process_time:.2f}ms")
    
    return response

# ==========================================
# MODELOS DE DATOS (Pydantic)
# ==========================================

class UserAuth(BaseModel):
    """
    Esquema para la validación automática de los datos de entrada en endpoints de autenticación.
    """
    username: str
    password: str

# ==========================================
# ENDPOINTS DE AUTENTICACIÓN
# ==========================================

@app.post("/api/v1/register")
def register(user: UserAuth):
    # 1. VALIDACIÓN DE POLÍTICA DE CONTRASEÑAS
    is_valid, msg = security.validate_password_policy(user.password, user.username)
    if not is_valid:
        logger.warning(f"Intento de registro fallido para '{user.username}': Contraseña débil.")
        raise HTTPException(status_code = 400, detail = msg)

    conn = database.get_connection()
    c = conn.cursor()

    # 2. GENERACIÓN DE CREDENCIALES SEGURAS
    salt, key  = security.hash_password(user.password)

    try:
        c.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                  (user.username, key, salt))
        conn.commit()
        logger.info(f"Nuevo usuario registrado exitosamente: '{user.username}'")
    except sqlite3.IntegrityError:
        logger.warning(f"Intento de registro fallido: Usuario '{user.username}' ya existe.")
        raise HTTPException(status_code = 400, detail = 'Usuario ya existe')
    finally:
        conn.close()
        
    return {"message": "Usuario registrado exitosamente"}


@app.post("/api/v1/login")
def login(user: UserAuth):
    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, failed_attempts, lockout_until FROM users WHERE username = ?", (user.username,))
    row = c.fetchone()

    # 1. VERIFICACIÓN DE EXISTENCIA
    if not row:
        conn.close()
        logger.warning(f"Intento de login fallido: Usuario '{user.username}' inexistente.")
        raise HTTPException(status_code = 401, detail = "Credenciales inválidas")

    stored_hash, salt, failed_attempts, lockout_until = row
    current_time = int(time.time())

    # 2. VERIFICACIÓN DE BLOQUEO TEMPORAL
    if lockout_until and current_time < lockout_until:
        conn.close()
        logger.warning(f"Intento de login bloqueado para '{user.username}': Cuenta bajo lockout temporal.")
        raise HTTPException(status_code = 403, detail = "Cuenta bloqueada temporalmente por múltiples intentos fallidos. Inténtalo más tarde.")

    if lockout_until and current_time >= lockout_until:
        failed_attempts = 0

    # 3. VERIFICACIÓN DE LA CONTRASEÑA
    _, computed_hash = security.hash_password(user.password, salt)
    
    if not security.secrets.compare_digest(stored_hash, computed_hash):
        failed_attempts += 1
        new_lockout = current_time + 300 if failed_attempts >= 3 else None
        
        c.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?", 
                  (failed_attempts, new_lockout, user.username))
        conn.commit()
        conn.close()
        logger.warning(f"Login fallido para '{user.username}': Credenciales incorrectas (Intento {failed_attempts}/3).")
        raise HTTPException(status_code = 401, detail = "Credenciales inválidas")

    # 4. GENERACIÓN DE SESIÓN
    session_token = security.secrets.token_hex(32)
    c.execute("UPDATE users SET failed_attempts = 0, lockout_until = NULL, session_token = ? WHERE username = ?", 
                  (session_token, user.username))
    conn.commit()
    conn.close()
    
    logger.info(f"Inicio de sesión exitoso para usuario '{user.username}'.")
    return {"message": "Se ha iniciado sesión con éxito.", "session_token": session_token}


@app.post("/api/v1/logout")
def logout(x_session_token: str = Header(None)):
    if not x_session_token:
        logger.warning("Intento de logout sin proporcionar token de sesión.")
        raise HTTPException(status_code = 400, detail = "Token de sesión no proporcionado.")
        
    conn = database.get_connection()
    c = conn.cursor()

    c.execute("UPDATE users SET session_token = NULL WHERE session_token = ?", (x_session_token,))
    
    if c.rowcount == 0:
        conn.close()
        logger.warning("Intento de logout con token inválido o sesión ya cerrada.")
        raise HTTPException(status_code = 401, detail = "Sesión inválida o ya cerrada.")
        
    conn.commit()
    conn.close()
    logger.info("Cierre de sesión ejecutado correctamente.")
    return {"message": "Sesión cerrada correctamente."}


# ==========================================
# ENDPOINTS DE TRANSACCIONES 
# ==========================================

@app.post("/api/v1/transfer")
async def transfer(
    request: Request,
    username: str = Header(...),
    x_nonce: str = Header(...),
    x_timestamp: str = Header(...),
    x_signature: str = Header(...)
):
    if not x_signature or not x_nonce or not x_timestamp:
        logger.warning(f"Petición de transferencia rechazada para '{username}': Cabeceras incompletas.")
        raise HTTPException(status_code = 400, detail = "Faltan cabeceras de seguridad.")

    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT session_token FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if not row or row[0] == None:
        logger.warning(f"Transferencia rechazada: Usuario '{username}' inexistente o sin sesión activa.")
        raise HTTPException(status_code = 401, detail = "Usuario inexistente o no autenticado")

    token = row[0]
    session_token = bytes.fromhex(token)
    
    current_time = int(time.time())
    if abs(current_time - float(x_timestamp)) > 60:
        logger.warning(f"Posible Replay Attack (Timestamp expirado) en cuenta '{username}'.")
        raise HTTPException(status_code = 400, detail = "Timestamp expirado (Posible Replay Attack)")

    conn = database.get_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO nonces(nonce, timestamp) VALUES (?, ?)",
                  (x_nonce, x_timestamp))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        logger.warning(f"Replay Attack interceptado (Nonce duplicado) en cuenta '{username}'.")
        raise HTTPException(status_code = 400, detail = "Replay Attack detectado")
    conn.close()

    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8')

    payload_to_verify = f"{body_str}|{x_nonce}|{x_timestamp}"
    if not security.verify_mac(payload_to_verify, session_token, x_signature):
        logger.warning(f"Posible MitM Attack: Firma HMAC inválida detectada para '{username}'.")
        raise HTTPException(status_code = 403, detail = "Firma MAC inválida. Integridad comprometida")

    payload = json.loads(body_bytes)
    conn = database.get_connection()
    c = conn.cursor()
    c.execute("INSERT INTO transactions(txId, origin_account, destination_account, amount, currency) VALUES (?, ?, ?, ?, ?)",
                (payload['txId'], payload['origin_account'], payload['destination_account'], payload['amount'], payload['currency']))
    conn.commit()
    conn.close()

    logger.info(f"Transacción exitosa procesada para '{username}': {payload['amount']} {payload['currency']} hacia {payload['destination_account']}")
    return {"status": "success", "message": "Transacción procesada con integridad verificada"}


if __name__ == "__main__":
    uvicorn.run(app, host = "127.0.0.1", port = 8080)