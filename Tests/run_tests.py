import requests
import time
import secrets
import json
import uuid
import sys
from pathlib import Path

# ==========================================
# CONFIGURACIÓN DE RUTAS E IMPORTACIONES
# ==========================================
# Permitimos importar módulos del directorio padre para reutilizar 
# las mismas funciones de seguridad (generación de MAC) que usa el servidor.
directorio_padre = Path(__file__).resolve().parent.parent
sys.path.append(str(directorio_padre))
import Server.security as security


BASE_URL = "http://127.0.0.1:8080"


def execute_test_suite():
    """
    Ejecuta un plan de pruebas automatizado (Integration Tests) contra la API.
    Verifica que los controles de seguridad criptográficos (HMAC, Nonces, Timestamps)
    funcionen correctamente y bloqueen vectores de ataque conocidos.
    """
    print("=====================================================")
    print("         EJECUCIÓN PLAN DE PRUEBAS INTEGRIDOS        ")
    print("=====================================================")


    # ==========================================
    # REQUISITO: AUTENTICACIÓN
    # ==========================================
    # Para poder firmar transacciones, necesitamos un token de sesión válido.
    # Simulamos el login de un usuario legítimo (previamente creado por seed.py).
    # CORREGIDO: Contraseña actualizada para cumplir con la nueva política
    creds = {"username": "Marcos", "password": "Secur3Bank!2026"}
    login_resp = requests.post(f"{BASE_URL}/api/v1/login", json = creds)
    if login_resp.status_code != 200:
        print("[!] ERROR CRÍTICO: No se pudo autenticar a 'Marcos'. Asegúrate de ejecutar seed.py y server.py primero.")
        return

    # Extraemos el token que usaremos como 'secret_key' para nuestros tests
    session_token = login_resp.json().get("session_token")
    # CORREGIDO: Uso de comillas simples
    print(login_resp.json().get('message'))

    # Datos base para una transferencia legítima
    tx_base = {
        "txId": str(uuid.uuid4()),
        "origin_account": "ES1122334455",
        "destination_account": "ES5544332211",
        "amount": 100.00,
        "currency": "EUR"
    }

    # ==========================================
    # TC-01: FLUJO NORMAL
    # ==========================================
    # Objetivo: Comprobar que una petición íntegra y bien firmada es aceptada.
    print("[TC-01] Pruebas de Transacción legítima...")
    body = json.dumps(tx_base, separators = (',', ':'))
    nonce = secrets.token_hex(16)
    timestamp = str(time.time())

    # Construcción del payload y firmado exacto como lo espera el servidor
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
    # CORREGIDO: Uso de comillas simples
    print(f" -> Resultado TC-01: Status {r.status_code} | Respuesta: {r.json().get('message')}")
    assert r.status_code == 200, "TC-01 Falló"


    # ==========================================
    # TC-02: ATAQUE MAN-IN-THE-MIDDLE (MitM)
    # ==========================================
    # Objetivo: Simular que un atacante intercepta la petición en tránsito y 
    # modifica el importe a su favor (de 100 a 10000 EUR), sin conocer el session_token.
    print("\n[TC-02] Prueba de Ataque MitM (Alteración de la cantidad a 10000 EUR)...")
    tampered_tx = tx_base.copy()
    tampered_tx["amount"] = 10000.00
    tampered_body = json.dumps(tampered_tx, separators = (',', ':'))
    mitm_headers = headers.copy()
    mitm_headers["X-Nonce"] = secrets.token_hex(16)# Renovamos el nonce para evitar el error de Replay antes que el de MitM

    # Enviamos el cuerpo alterado PERO mantenemos la firma original.
    # El servidor recalculará el HMAC con el body alterado, no coincidirá con la firma y lo rechazará.
    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = tampered_body, headers = mitm_headers)
    # CORREGIDO: Uso de comillas simples
    print(f" -> Resultado TC-02: Status {r.status_code} | Respuesta: {r.json().get('detail')}")
    assert r.status_code == 403, "TC-02 Falló"


    # ==========================================
    # TC-03: ATAQUE DE REPETICIÓN (Replay Attack)
    # ==========================================
    # Objetivo: Simular que un atacante guarda la petición del TC-01 (que era válida)
    # y la reenvía íntegra para cobrar los 100 EUR por segunda vez.
    print("\n[TC-03] Prueba de Ataque de Replay (Re-envío del mismo paquete exactamente)...")
    # Enviamos exactamente el mismo 'body' y 'headers' (mismo nonce) del TC-01
    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
    # El servidor debe detectar en SQLite que el 'X-Nonce' ya fue procesado y rechazarlo.
    # CORREGIDO: Uso de comillas simples
    print(f" -> Resultado TC-03: Status {r.status_code} | Respuesta: {r.json().get('detail')}")
    assert r.status_code == 400, "TC-03 Falló"


    # ==========================================
    # TC-04: TIMESTAMP EXPIRADO (Delayed Replay)
    # ==========================================
    # Objetivo: Verificar que la "ventana de tiempo" funciona. Incluso si el atacante
    # genera un nuevo Nonce y firma todo correctamente (quizás robó temporalmente el token),
    # el servidor debe rechazar peticiones artificialmente retrasadas.
    print("\n[TC-04] Prueba Timestamp expirado (Mensaje de hace 5 minutos)...")
    old_timestamp = str(time.time() - 300)# Restamos 300 segundos (5 min) al tiempo actual
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
    # CORREGIDO: Uso de comillas simples
    print(f" -> Resultado TC-04: Status {r.status_code} | Respuesta: {r.json().get('detail')}")
    assert r.status_code == 400, "TC-04 Falló"

    
    # ==========================================
    # TC-05: USUARIO NO AUTENTICADO (Impersonation)
    # ==========================================
    # Objetivo: Probar si se puede ejecutar una transacción en nombre de otra persona.
    print("\n[TC-05] Prueba Usuario Inexistente / Sin Sesión...")
    headers["username"] = "Carlos"  # Cambiamos el usuario al vuelo

    # El servidor buscará el token de "Carlos", intentará validar el HMAC y fallará,
    # o detectará que "Carlos" no tiene una sesión activa (token = NULL).
    r = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
    # CORREGIDO: Uso de comillas simples
    print(f" -> Resultado TC-05: Status {r.status_code} | Respuesta: {r.json().get('detail')}")
    assert r.status_code == 401, "TC-05 Falló"
    

    # ==========================================
    # REQUISITO: LIMPIEZA DE SESIÓN
    # ==========================================
    # CORREGIDO: Uso de comillas simples
    logout_resp = requests.post(f"{BASE_URL}/api/v1/logout", headers = {"X-Session-Token": session_token})
    print("\n",logout_resp.json().get('message'))


    print("=====================================================")
    print("         TODAS LAS PRUEBAS HAN SIDO SUPERADAS        ")
    print("=====================================================")


if __name__ == "__main__":
    execute_test_suite()