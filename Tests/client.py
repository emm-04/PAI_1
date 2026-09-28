import requests
import time
import secrets
import hmac
import hashlib
import json
import uuid


BASE_URL = "http://127.0.0.1:8080"

def run_client():
    # 1. Registro y Login
    creds = {"username": "ismael", "password": "SuperSecretPassword123"}
    register_resp = requests.post(f"{BASE_URL}/api/v1/register", json = creds)
    if register_resp.json().get("message") == None:
        print(register_resp.json().get("detail"))
    else:
        print(register_resp.json().get("message"))

    
    login_resp = requests.post(f"{BASE_URL}/api/v1/login", json = creds)
    session_token = login_resp.json().get("session_token")
    if login_resp.json().get("message") == None:
        print(login_resp.json().get("detail"))
    else:
        print(login_resp.json().get("message"))

    
    # 2. Preparar transacción
    tx_data = {
        "txId": str(uuid.uuid4),
        "origin_account": "ES123456789",
        "destination_account": "ES987654321",
        "amount": 500.00,
        "currency": "EUR"
    }
    body_str = json.dumps(tx_data, separators = (',', ':'))


    # 3. Datos de seguridad
    nonce = secrets.token_hex(16)
    timestamp = str(time.time())


    # 4. Generar Firma HMAC
    payload_to_sign = f"{body_str}|{nonce}|{timestamp}"
    signature = hmac.new(bytes.fromhex(session_token), payload_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()


    # 5. Enviar petición
    headers = {
        "Content-Type": "application/json",
        "username": creds["username"],
        "X-Nonce": nonce,
        "X-Timestamp": timestamp,
        "X-signature": signature
    }

    response = requests.post(f"{BASE_URL}/api/v1/transfer", data = body_str, headers = headers)
    print(f"Respuesta del Servidor: {response.status_code} - {response.text}")

    logout_resp = requests.post(f"{BASE_URL}/api/v1/logout", headers = {"X-Session-Token": session_token})
    if logout_resp.json().get("message") == None:
        print(logout_resp.json().get("detail"))
    else:
        print(logout_resp.json().get("message"))
    

if __name__ == "__main__":
    run_client()