import hashlib
import secrets
import hmac

# ==========================================
# MÓDULO DE SEGURIDAD CRIPTOGRÁFICA
# ==========================================
# Contiene las funciones core para proteger el almacenamiento 
# de credenciales y garantizar la integridad de los mensajes.

#Derivación de claves seguras (Requisito de almacenamiento)
def hash_password(password: str, salt: bytes = None) -> tuple:
    """
    Deriva una clave segura a partir de una contraseña en texto plano.
    Utiliza PBKDF2 (Password-Based Key Derivation Function 2), que está diseñado 
    para ser computacionalmente costoso y ralentizar ataques de fuerza bruta.
    
    Args:
        password (str): La contraseña en texto plano del usuario.
        salt (bytes, opcional): Semilla criptográfica. Si no se provee, se genera una nueva.
        
    Returns:
        tuple: (salt_utilizado, hash_generado)
    """

    # 1. GENERACIÓN DEL SALT
    # Si es un usuario nuevo, generamos un salt criptográficamente seguro de 16 bytes.
    # El salt asegura que dos usuarios con la misma contraseña tengan hashes completamente distintos,
    # invalidando el uso de Rainbow Tables (tablas precalculadas de hashes).
    if salt is None:
        salt = secrets.token_bytes(16) #Salt único de 16 bytes

    # 2. DERIVACIÓN DE LA CLAVE
    # Usamos HMAC-SHA256 con 100,000 iteraciones (work factor).
    # Este alto número de iteraciones hace que calcular el hash sea "lento" a propósito.
    # Para un usuario legítimo toma una fracción de segundo, pero para un atacante 
    # intentando probar millones de contraseñas por segundo, hace que el ataque sea inviable.
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt, key

#Generación de la firma de la transacción
def generate_mac(payload: str, secret_key: bytes) -> str:
    """
    Genera un Código de Autenticación de Mensaje (MAC) basado en Hash (HMAC).
    Garantiza dos cosas:
    1. Integridad: El mensaje (payload) no ha sido alterado.
    2. Autenticidad: El mensaje fue creado por alguien que posee la secret_key.
    
    Args:
        payload (str): Los datos que queremos proteger/firmar (ej. datos de una transacción).
        secret_key (bytes): Clave secreta compartida entre las partes o propia del servidor.
        
    Returns:
        str: La firma HMAC en formato hexadecimal.
    """
    # Se utiliza HMAC en combinación con SHA-256. 
    # HMAC es resistente a ataques de extensión de longitud a los que las funciones 
    # hash tradicionales (como SHA-256 por sí solo) son vulnerables.
    return hmac.new(secret_key, payload.encode('utf-8'), hashlib.sha256).hexdigest()

#Mitigación de Canal Lateral
def verify_mac(payload: str, secret_key: bytes, received_mac: str) -> bool:
    """
    Verifica que un MAC recibido coincida con el MAC esperado para un payload dado.
    Implementa mitigación contra Ataques de Canal Lateral (Timing Attacks).
    
    Args:
        payload (str): Los datos recibidos.
        secret_key (bytes): La clave secreta para regenerar la firma.
        received_mac (str): La firma proporcionada junto con el payload.
        
    Returns:
        bool: True si la firma es válida, False en caso contrario.
    """
    # Primero, calculamos cuál debería ser la firma correcta para esos datos
    expected_mac = generate_mac(payload, secret_key)
    # MITIGACIÓN DE TIMING ATTACK (Ataque de tiempo):
    # NUNCA se debe usar '==' para comparar hashes o tokens de seguridad.
    # El operador '==' compara byte por byte y devuelve False en cuanto encuentra una diferencia.
    # Un atacante podría medir en microsegundos cuánto tarda en fallar la comparación 
    # y así adivinar la firma carácter por carácter.
    # 'secrets.compare_digest' compara las cadenas en "tiempo constante", tardando siempre 
    # lo mismo sin importar dónde esté el error.
    return secrets.compare_digest(expected_mac, received_mac)

