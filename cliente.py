import requests
import time
import hmac
import hashlib
import json
import uuid

url = "http://localhost:8080/api/v1/transfer"
SHARED_SECRET = b"esta_es_una_clave_compartida_muy_segura_256b"

# 1. Preparar los datos
payload = {
    "tx_id": str(uuid.uuid4()),
    "origin_account": "ES1234567890123456789012",
    "destination_account": "ES9876543210987654321098",
    "amount": 1500.50,
    "currency": "EUR"
}

# Codificar a bytes tal cual se enviará para que el Hash coincida
body_bytes = json.dumps(payload).encode('utf-8')

# 2. Generar parámetros de seguridad (HMAC, Nonce, Timestamp)[cite: 1]
timestamp = int(time.time())
nonce = str(uuid.uuid4())
signature = hmac.new(SHARED_SECRET, body_bytes, hashlib.sha256).hexdigest()

headers = {
    "Content-Type": "application/json",
    "X-Signature": signature,
    "X-Nonce": nonce,
    "X-Timestamp": str(timestamp)
}

print("--- PRUEBA 1: Flujo Legítimo ---")
response_ok = requests.post(url, data=body_bytes, headers=headers)
print(f"Status: {response_ok.status_code}")
print(f"Respuesta: {response_ok.text}\n")

print("--- PRUEBA 2: Ataque de Repetición (Replay) ---")
print("Reenviando exactamente el mismo paquete capturado...")
response_replay = requests.post(url, data=body_bytes, headers=headers)
print(f"Status: {response_replay.status_code}")
print(f"Respuesta: {response_replay.text}")