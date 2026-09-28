import hashlib
import secrets
import hmac


#Derivación de claves seguras (Requisito de almacenamiento)
def hash_password(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = secrets.token_bytes(16) #Salt único de 16 bytes

    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, key

#Generación de la firma de la transacción
def generate_mac(payload: str, secret_key: bytes) -> str:
    return hmac.new(secret_key, payload.encode('utf-8'), hashlib.sha256).hexdigest()

#Mitigación de Canal Lateral
def verify_mac(payload: str, secret_key: bytes, received_mac: str) -> bool:
    expected_mac = generate_mac(payload, secret_key)
    return secrets.compare_digest(expected_mac, received_mac)

