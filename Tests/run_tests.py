import requests
import time
import secrets
import json
import uuid
import sys
from pathlib import Path
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))
import Server.security as security


BASE_URL = "http://127.0.0.1:8080"


def execute_test_suite():
    print("=====================================================")
    print("         EJECUCIÓN PLAN DE PRUEBAS INTEGRIDOS        ")
    print("=====================================================")



    # --- Autenticación inicial de usuario ---
    creds = {"username": "Marcos", "password": "marcosSecurePass2026"}
    login_resp = requests.post(f"{BASE_URL}/api/v1/login", json = creds)
    if login_resp.status_code != 200:
        print("[!] ERROR CRÍTICO: No se pudo autenticar a 'Marcos'. Asegúrate de ejecutar seed.py y server.py primero.")
        return

    session_token = login_resp.json().get("session_token")
    print(login_resp.json().get("message"))

    tx_base = {
        "txId": str(uuid.uuid4()),
        "origin_account": "ES1122334455",
        "destination_account": "ES5544332211",
        "amount": 100.00,
        "currency": "EUR"
    }

    # --- TC-01: Transacción legítima ---
    print("[TC-01] Pruebas de Transacción legítima...")
    body = json.dumps(tx_base, separators = (',', ':'))
    nonce = secrets.token_hex(16)
    timestamp = str(time.time())
    payload = f"{body}|{nonce}|{timestamp}"
    signature = security.generate_mac(payload, bytes.fromhex(session_token))

    headers = {
        "Content-Type": "application/json",
        "username": "Marcos",
        "X-Nonce": nonce,
        "X-Timestamp": timestamp,
        "X-Signature": signature
    }

    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
    print(f" -> Resultado TC-01: Status {r.status_code} | Respuesta: {r.json().get("message")}")
    assert r.status_code == 200, "TC-01 Falló"


    # --- TC-02: Ataque Man-in-the-Middle (Modificación de datos) ---
    print("\n[TC-02] Prueba de Ataque MitM (Alteración de la cantidad a 10000 EUR)...")
    tampered_tx = tx_base.copy()
    tampered_tx["amount"] = 10000.00
    tampered_body = json.dumps(tampered_tx, separators = (',', ':'))
    mitm_headers = headers.copy()
    mitm_headers["X-Nonce"] = secrets.token_hex(16)

    # Se envía el cuerpo alterado manteniendo la firma original
    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = tampered_body, headers = mitm_headers)
    print(f" -> Resultado TC-02: Status {r.status_code} | Respuesta: {r.json().get("detail")}")
    assert r.status_code == 403, "TC-02 Falló"


    # --- TC-03: Ataque de Replay (Reutilización de Nonce) ---
    print("\n[TC-03] Prueba de Ataque de Replay (Re-envío del mismo paquete exactamente)...")
    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
    print(f" -> Resultado TC-03: Status {r.status_code} | Respuesta: {r.json().get("detail")}")
    assert r.status_code == 400, "TC-03 Falló"


    # --- TC-04: Timestamp expirado ---
    print("\n[TC-04] Prueba Timestamp expirado (Mensaje de hace 5 minutos)...")
    old_timestamp = str(time.time() - 300)
    new_nonce = secrets.token_hex(16)
    new_payload = f"{body}|{new_nonce}|{old_timestamp}"
    signature_expired = security.generate_mac(new_payload, bytes.fromhex(session_token))

    expired_headers = {
        "Content-Type": "application/json",
        "username": "Marcos",
        "X-Nonce": new_nonce,
        "X-Timestamp": old_timestamp,
        "X-Signature": signature_expired
    }

    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = expired_headers)
    print(f" -> Resultado TC-04: Status {r.status_code} | Respuesta: {r.json().get("detail")}")
    assert r.status_code == 400, "TC-04 Falló"

    
    # --- TC-05: Usuario no autenticado ---
    print("\n[TC-05] Prueba Usuario Inexistente / Sin Sesión...")
    headers["username"] = "Carlos"
    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
    print(f" -> Resultado TC-05: Status {r.status_code} | Respuesta: {r.json().get("detail")}")
    assert r.status_code == 401, "TC-05 Falló"
    

    # --- Cerrar sesión del usuario ---
    logout_resp = requests.post(f"{BASE_URL}/api/v1/logout", headers = {"X-Session-Token": session_token})
    print("\n",logout_resp.json().get("message"))


    print("=====================================================")
    print("         TODAS LAS PRUEBAS HAN SIDO SUPERADAS        ")
    print("=====================================================")


if __name__ == "__main__":
    execute_test_suite()