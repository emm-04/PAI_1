# SecBank (PAI_1)

Este proyecto es una arquitectura diseñada para simular los controles de seguridad y registro de un entorno bancario real, yendo más allá de una simple base de datos de almacenamiento.

## 1. Seguridad de Cuentas y Autenticación
La tabla `users` está estructurada para proteger la identidad y el acceso de los clientes aplicando principios criptográficos:

* **Contraseñas seguras (`password_hash` y `salt`):** El sistema está diseñado para no guardar contraseñas en texto plano. Utiliza un *salt* (datos aleatorios añadidos a la contraseña del usuario) junto con un algoritmo de *hashing* para defender la base de datos contra ataques de fuerza bruta o tablas arcoíris.
* **Defensa activa (`failed_attempts`):** Este contador, que se inicializa por defecto en `0`, permite a la aplicación registrar los inicios de sesión fallidos. Con este dato, el sistema puede bloquear temporalmente una cuenta ante intentos repetidos de adivinar una credencial.
* **Manejo de sesiones (`session_token`):** Tras una autenticación exitosa, el sistema genera un token temporal. Esto permite al usuario operar de forma continua sin enviar su usuario y contraseña en cada petición, minimizando el riesgo de interceptación en la red.

## 2. Protección Avanzada (Nonces)
La tabla `nonces` es una medida de seguridad crítica para mitigar los ataques de repetición (*Replay Attacks*):

* **Tokens de un solo uso (`nonce`):** Un *Number Used Once* es una cadena de texto única que el cliente debe generar y adjuntar en cada operación crítica (como una transferencia).
* **Caducidad temporal (`timestamp`):** Al guardar la marca de tiempo de la solicitud, el servidor valida la vigencia de la petición. Si un atacante intercepta una transferencia legítima e intenta reenviarla minutos después, la base de datos detectará que el *nonce* ya fue utilizado o que el *timestamp* ha caducado, bloqueando la operación.

## 3. Trazabilidad de Operaciones
La tabla `transactions` asegura que cada movimiento económico quede documentado de forma estructurada para facilitar auditorías:

* **Identificador inequívoco (`tx_id UNIQUE`):** Cada operación recibe un ID de transacción único que previene registros duplicados y permite la emisión de justificantes bancarios precisos.
* **Registro contable:** Detalla el flujo exacto del capital capturando la cuenta de origen (`origin_account`), la cuenta de destino (`destination_account`), el importe exacto con soporte para decimales (`amount REAL`) y la moneda utilizada (`currency TEXT`).

## 4. Flujo de Infraestructura
* **`database.py`:** Actúa como el arquitecto del sistema. Al ejecutarse directamente, llama a la función `init_db()`, la cual construye las tablas de forma segura (solo `IF NOT EXISTS`), consolida los cambios en disco (`conn.commit()`) y cierra la conexión limpiamente (`conn.close()`).
* **`cliente.py`:** Una vez inicializada la base de datos, este archivo complementario utiliza la infraestructura creada para gestionar la inserción de usuarios, generar transacciones y verificar contraseñas.