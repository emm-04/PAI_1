from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
import time
import security # Asegúrate de que este archivo ahora contenga la función validate_password_policy
import sqlite3
import json
import uvicorn
import sys
from pathlib import Path

# ==========================================
# CONFIGURACIÓN DE RUTAS E IMPORTACIONES
# ==========================================
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))
import DB.database as database


# Inicialización de la aplicación FastAPI
app = FastAPI()

# ==========================================
# MODELOS DE DATOS (Pydantic)
# ==========================================

class UserAuth(BaseModel):
    """
    Esquema para la validación automática de los datos de entrada en endpoints de autenticación.
    FastAPI rechazará automáticamente peticiones que no cumplan este formato.
    """
    username: str
    password: str

# ==========================================
# ENDPOINTS DE AUTENTICACIÓN
# ==========================================

@app.post("/api/v1/register")
def register(user: UserAuth):
    # 1. VALIDACIÓN DE POLÍTICA DE CONTRASEÑAS (NUEVO)
    is_valid, msg = security.validate_password_policy(user.password, user.username)
    if not is_valid:
        raise HTTPException(status_code = 400, detail = msg)

    conn = database.get_connection()
    c = conn.cursor()

    # 2. GENERACIÓN DE CREDENCIALES SEGURAS
    # Generamos el hash y el salt a través del módulo de seguridad.
    # NUNCA guardamos la contraseña plana 'user.password'.
    salt, key  = security.hash_password(user.password)

    try:
        c.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                  (user.username, key, salt))
        conn.commit()
    except sqlite3.IntegrityError:
        # Prevención de enumeración/fuga de información: 
        # Devuelve un 400 claro si el usuario ya existe, sin exponer detalles de la BD.
        raise HTTPException(status_code = 400, detail = 'Usuario ya existe')
    finally:
        conn.close()
        
    return {"message": "Usuario registrado exitosamente"}


@app.post("/api/v1/login")
def login(user: UserAuth):
    """
    Autentica a un usuario y genera un token de sesión de un solo uso.
    Implementa protección contra fuerza bruta con bloqueos temporales 
    y previene ataques de tiempo.
    """
    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, failed_attempts, lockout_until FROM users WHERE username = ?", (user.username,))
    row = c.fetchone()

    # 1. VERIFICACIÓN DE EXISTENCIA
    if not row:
        conn.close()
        # Usamos un mensaje genérico ("Credenciales inválidas") para evitar 
        # ataques de enumeración de usuarios.
        raise HTTPException(status_code = 401, detail = "Credenciales inválidas")

    stored_hash, salt, failed_attempts, lockout_until = row
    current_time = int(time.time())

    # 2. VERIFICACIÓN DE BLOQUEO TEMPORAL (CORREGIDO)
    if lockout_until and current_time < lockout_until:
        conn.close()
        raise HTTPException(status_code = 403, detail = "Cuenta bloqueada temporalmente por múltiples intentos fallidos. Inténtalo más tarde.")

    # Si el tiempo de bloqueo ya expiró, reseteamos lógicamente los intentos para esta prueba
    if lockout_until and current_time >= lockout_until:
        failed_attempts = 0

    # 3. VERIFICACIÓN DE LA CONTRASEÑA
    _, computed_hash = security.hash_password(user.password, salt)
    
    # Utilizamos compare_digest para evitar Timing Attacks
    if not security.secrets.compare_digest(stored_hash, computed_hash):
        failed_attempts += 1
        # Si llega a 3 intentos, bloqueamos por 5 minutos (300 segundos)
        new_lockout = current_time + 300 if failed_attempts >= 3 else None
        
        c.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE username = ?", 
                  (failed_attempts, new_lockout, user.username))
        conn.commit()
        conn.close()
        raise HTTPException(status_code = 401, detail = "Credenciales inválidas")


    # 4. GENERACIÓN DE SESIÓN (Estado autenticado)
    # Generamos un token criptográficamente seguro de 32 bytes (64 caracteres hex)
    session_token = security.secrets.token_hex(32)
    
    # Reseteamos fallos y limpiamos el bloqueo
    c.execute("UPDATE users SET failed_attempts = 0, lockout_until = NULL, session_token = ? WHERE username = ?", 
                  (session_token, user.username))
    conn.commit()
    conn.close()
    
    return {"message": "Se ha iniciado sesión con éxito.", "session_token": session_token}


@app.post("/api/v1/logout")
def logout(x_session_token: str = Header(None)):
    """
    Cierra la sesión del usuario invalidando el token en la base de datos (Stateful Session).
    """
    if not x_session_token:
        raise HTTPException(status_code = 400, detail = "Token de sesión no proporcionado.")
        
    conn = database.get_connection()
    c = conn.cursor()

    # Invalidamos el token estableciéndolo a NULL
    c.execute("UPDATE users SET session_token = NULL WHERE session_token = ?", (x_session_token,))
    
    if c.rowcount == 0:
        # Si rowcount es 0, significa que el token no existía en la base de datos
        conn.close()
        raise HTTPException(status_code = 401, detail = "Sesión inválida o ya cerrada.")
        
    conn.commit()
    conn.close()
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
    """
    Procesa una transferencia de fondos.
    Este es el endpoint más crítico. Implementa firma HMAC, mitigación de Replay Attacks 
    (mediante Nonces y Timestamps) y validación de sesión.
    """
    # 0. VALIDACIÓN DE CABECERAS Y SESIÓN
    if not x_signature or not x_nonce or not x_timestamp:
        raise HTTPException(status_code = 400, detail = "Faltan cabeceras de seguridad.")

    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT session_token FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if not row or row[0] == None:
        raise HTTPException(status_code = 401, detail = "Usuario inexistente o no autenticado")

    # El token de sesión actuará como nuestra clave secreta compartida (Secret Key) para el HMAC
    token = row[0]
    session_token = bytes.fromhex(token)
    
    # 1. MITIGACIÓN DE REPLAY ATTACK (Ventana de Tiempo)
    # Evita que un atacante guarde una petición interceptada y la envíe horas después.
    current_time = int(time.time())
    if abs(current_time - float(x_timestamp)) > 60: # 60 segundos de validez
        raise HTTPException(status_code = 400, detail = "Timestamp expirado (Posible Replay Attack)")

    # 2. MITIGACIÓN DE REPLAY ATTACK (Nonce Único)
    # Evita que, dentro de esos 60 segundos, el atacante duplique la misma petición.
    conn = database.get_connection()
    c = conn.cursor()
    try:
        # Si el nonce ya existe en la BD, lanzará IntegrityError
        c.execute("INSERT INTO nonces(nonce, timestamp) VALUES (?, ?)",
                  (x_nonce, x_timestamp))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code = 400, detail = "Replay Attack detectado")
    
    conn.close()

    # 3. VERIFICACIÓN DE INTEGRIDAD HMAC (Mitigación MitM)
    # Evita que un atacante "Man-in-the-Middle" altere la cantidad (amount) o el destinatario.
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8')

    # Reconstruimos el payload exacto que el cliente debe haber firmado
    payload_to_verify = f"{body_str}|{x_nonce}|{x_timestamp}"
    # Verificamos que la firma recibida coincide con la que calculamos nosotros
    if not security.verify_mac(payload_to_verify, session_token, x_signature):
        raise HTTPException(status_code = 403, detail = "Firma MAC inválida. Integridad comprometida")

    # 4. EJECUCIÓN DE LA TRANSACCIÓN
    # Si llegamos aquí, la petición es fresca, única, íntegra y autética.
    payload = json.loads(body_bytes)
    conn = database.get_connection()
    c = conn.cursor()
    # Usamos consultas parametrizadas (?) para prevenir Inyección SQL
    c.execute("INSERT INTO transactions(txId, origin_account, destination_account, amount, currency) VALUES (?, ?, ?, ?, ?)",
                (payload['txId'], payload['origin_account'], payload['destination_account'], payload['amount'], payload['currency']))
    conn.commit()
    conn.close()

    return {"status": "success", "message": "Transacción procesada con integridad verificada"}


if __name__ == "__main__":
    uvicorn.run(app, host = "127.0.0.1", port = 8080)