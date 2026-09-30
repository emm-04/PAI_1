import hashlib
import secrets
import hmac
import re


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


def validate_password_policy(password: str, username: str = None) -> tuple[bool, str]:
    """
    Valida que la contraseña cumpla con la política de seguridad:
    - Mínimo 8 caracteres de longitud.
    - Al menos una letra mayúscula.
    - Al menos una letra minúscula.
    - Al menos un número.
    - Al menos un carácter especial.
    - No contener el nombre de usuario.
    """
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    
    if not re.search(r"[A-Z]", password):
        return False, "La contraseña debe incluir al menos una letra mayúscula."
        
    if not re.search(r"[a-z]", password):
        return False, "La contraseña debe incluir al menos una letra minúscula."
        
    if not re.search(r"\d", password):
        return False, "La contraseña debe incluir al menos un número."
        
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "La contraseña debe incluir al menos un carácter especial (ej. !@#$%^&*)."
        
    if username and username.lower() in password.lower():
        return False, "La contraseña no puede contener el nombre de usuario."
        
    return True, "Contraseña válida"


