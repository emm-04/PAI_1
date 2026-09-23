import requests
import time
import hmac
import hashlib
import json
import uuid

url = "http://localhost:8080/api/v1/transfer"
SHARED_SECRET = b"esta_es_una_clave_compartida_muy_segura_256b"

# 1. El cliente legítimo prepara su transacción
payload_legitimo = {
    "tx_id": str(uuid.uuid4()),
    "origin_account": "ES1234567890123456789012",
    "destination_account": "ES9876543210987654321098",
    "amount": 100.00,
    "currency": "EUR"
}
body_legitimo_bytes = json.dumps(payload_legitimo).encode('utf-8')

# Genera su firma HMAC, Nonce y Timestamp válidos
signature_legitima = hmac.new(SHARED_SECRET, body_legitimo_bytes, hashlib.sha256).hexdigest()
headers = {
    "Content-Type": "application/json",
    "X-Signature": signature_legitima,
    "X-Nonce": str(uuid.uuid4()),
    "X-Timestamp": str(int(time.time()))
}

# 2. EL ATACANTE INTERCEPTA EL MENSAJE (MitM)
print("--- SIMULACIÓN DE ATAQUE MAN-IN-THE-MIDDLE ---")
print("Atacante intercepta el paquete y cambia el importe a 9999.99 EUR...")

payload_alterado = payload_legitimo.copy()
payload_alterado["amount"] = 9999.99  # El atacante modifica los datos
body_alterado_bytes = json.dumps(payload_alterado).encode('utf-8')

# El atacante envía el cuerpo alterado, pero con la firma original (no conoce la clave)
response_mitm = requests.post(url, data=body_alterado_bytes, headers=headers)

print(f"Status del servidor: {response_mitm.status_code}")
print(f"Respuesta del servidor: {response_mitm.text}")