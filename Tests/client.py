import requests
import time
import secrets
import hmac
import hashlib
import json
import uuid

# ==========================================
# CONFIGURACIÓN DEL CLIENTE
# ==========================================
BASE_URL = "http://127.0.0.1:8080"

def run_client():
    """
    Simula el comportamiento de un cliente legítimo (como una app móvil o web) 
    interactuando con la API de SecBank. Demuestra el flujo completo: 
    registro, autenticación, firma criptográfica de transacciones y cierre de sesión.
    """

    # ==========================================
    # 1. REGISTRO Y AUTENTICACIÓN
    # ==========================================
    creds = {"username": "ismael", "password": "SuperSecretPassword123"}

    # Intentamos registrar al usuario. Si ya existe, el servidor devolverá un error, 
    # pero nuestro código lo manejará leyendo el campo 'detail' de FastAPI.
    register_resp = requests.post(f"{BASE_URL}/api/v1/register", json = creds)
    if register_resp.json().get("message") == None:
        print(register_resp.json().get("detail"))
    else:
        print(register_resp.json().get("message"))

    # Iniciamos sesión para obtener el Session Token. 
    # Este token actuará como nuestra "Clave Secreta Compartida" para firmar 
    # operaciones posteriores sin tener que enviar la contraseña en cada petición.
    login_resp = requests.post(f"{BASE_URL}/api/v1/login", json = creds)
    session_token = login_resp.json().get("session_token")
    if login_resp.json().get("message") == None:
        print(login_resp.json().get("detail"))
    else:
        print(login_resp.json().get("message"))

    
    # ==========================================
    # 2. PREPARACIÓN DE LA TRANSACCIÓN
    # ==========================================
    tx_data = {
        "txId": str(uuid.uuid4),
        "origin_account": "ES123456789",
        "destination_account": "ES987654321",
        "amount": 500.00,
        "currency": "EUR"
    }

    # DETALLE CRÍTICO DE SEGURIDAD:
    # Usamos separators=(',', ':') para eliminar cualquier espacio en blanco del JSON.
    # Si el cliente firma el string `{"amount": 500}` pero envía `{"amount":500}`, 
    # el servidor calculará un hash distinto y rechazará la petición. 
    # La serialización debe ser estrictamente determinista.
    body_str = json.dumps(tx_data, separators = (',', ':'))


    # ==========================================
    # 3. DATOS DE SEGURIDAD (ANTI-REPLAY)
    # ==========================================
    # Nonce: "Number used ONCE". Un valor aleatorio para que esta petición 
    # sea criptográficamente distinta a cualquier otra idéntica en el pasado
    nonce = secrets.token_hex(16)
    # Timestamp: Limita la "ventana de tiempo" en la que esta petición es válida (ej. 60 segundos).
    timestamp = str(time.time())


    # ==========================================
    # 4. GENERACIÓN DE LA FIRMA HMAC
    # ==========================================
    # Concatenamos el cuerpo exacto, el nonce y el timestamp.
    # Si un atacante intercepta esto e intenta cambiar el 'amount' a 5000, 
    # la firma HMAC se invalidará porque no conoce el 'session_token' para refirmarlo.
    payload_to_sign = f"{body_str}|{nonce}|{timestamp}"

    # Firmamos utilizando HMAC-SHA256 y convertimos el token hexadecimal a bytes.
    signature = hmac.new(bytes.fromhex(session_token), payload_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()


    # ==========================================
    # 5. ENVÍO DE LA PETICIÓN PROTEGIDA
    # ==========================================
    # Los metadatos de seguridad viajan en las cabeceras HTTP (Headers), 
    # manteniendo el cuerpo (Body) limpio solo con los datos de negocio.
    headers = {
        "Content-Type": "application/json",
        "username": creds["username"],
        "X-Nonce": nonce,
        "X-Timestamp": timestamp,
        "X-signature": signature     # El servidor usará esto para verificar la integridad
    }

    # Usamos 'data=body_str' en lugar de 'json=tx_data' para garantizar que 'requests' 
    # envíe exactamente el string que acabamos de firmar, sin re-serializarlo.
    response = requests.post(f"{BASE_URL}/api/v1/transfer", data = body_str, headers = headers)
    print(f"Respuesta del Servidor: {response.status_code} - {response.text}")


    # ==========================================
    # 6. CIERRE DE SESIÓN SEGURO
    # ==========================================
    # Invalida el token en el lado del servidor. Una buena práctica de seguridad 
    # para reducir la ventana de exposición si el token es robado.
    logout_resp = requests.post(f"{BASE_URL}/api/v1/logout", headers = {"X-Session-Token": session_token})
    if logout_resp.json().get("message") == None:
        print(logout_resp.json().get("detail"))
    else:
        print(logout_resp.json().get("message"))
    

if __name__ == "__main__":
    run_client()