import streamlit
import requests
import time
import secrets
import json
import uuid
import Server.security as security

def web_page():
    streamlit.set_page_config(
        page_title = "SecBank - IntegriDos",
        page_icon = "🏦",
        layout = "wide"
    )

    BASE_URL = "http://127.0.0.1:8080"


    # Iniciación de variables de estado de sesión
    if "authenticated" not in streamlit.session_state:
        streamlit.session_state.authenticated = False
    if "username" not in streamlit.session_state:
        streamlit.session_state.username = ""
    if "session_token" not in streamlit.session_state:
        streamlit.session_state.session_token = ""


    # Header de la aplicación
    streamlit.title("🏦 SecBank - Sistema de Transacciones IntegriDos")
    streamlit.caption("Capa de Aplicación Segura: Firma HMAC-SHA256 | Protección Anti-Replay | Compare Digest")



    # ==============================================================
    #          PANTALLA DE AUTENTICACIÓN (LOGIN / REGISTRO)
    # ==============================================================

    if not streamlit.session_state.authenticated:
        streamlit.subheader("Acceso a la Plataforma")
        tab_login, tab_register = streamlit.tabs(["Iniciar Sesión", "Registrar Nuevo Usuario"])

        with tab_login:
            with streamlit.form("login_form"):
                user_input = streamlit.text_input("Usuario", value = "Marcos")
                pass_input = streamlit.text_input("Contraseña", type = "password", value = "marcosSecurePass2026")
                btn_login = streamlit.form_submit_button("Iniciar sesión")

                if btn_login:
                    try:
                        res = requests.post(f"{BASE_URL}/api/v1/login", json = {"username": user_input, "password": pass_input})
                        if res.status_code == 200:
                            streamlit.session_state.authenticated = True
                            streamlit.session_state.username = user_input
                            streamlit.session_state.session_token = res.json().get("session_token")
                            streamlit.success("Se ha iniciado sesión correctamente.")
                            streamlit.rerun()
                        else:
                            streamlit.error(f"Error {res.status_code}: {res.json().get("detail")}")
                    except Exception as e:
                        streamlit.error(f"Error de conexión con el servidor: {e}")

        with tab_register:
            with streamlit.form("register_form"):
                reg_user = streamlit.text_input("Nuevo Usuario")
                reg_pass = streamlit.text_input("Nueva Contraseña", type = "password")
                btn_register = streamlit.form_submit_button("Registrar Usuario")

                if btn_register:
                    if reg_user and reg_pass:
                        res = requests.post(f"{BASE_URL}/api/v1/register", json = {"username": reg_user, "password": reg_pass})
                        if res.status_code == 200:
                            streamlit.success("Usuario registrado con éxito. Ya puedes iniciar sesión.")
                        else:
                            streamlit.error(f"Error: {res.json().get("detail")}")
                    else:
                        streamlit.warning("Completa todos los campos.")



    # ===============================================================
    #              PANEL PRINCIPAL (USUARIO AUTENTICADO)
    # ===============================================================

    else:
        # Barra Superior de Sesión
        col_user, col_key, col_logout = streamlit.columns([3, 5, 2])
        with col_user:
            streamlit.markdown(f"**Usuario:** `{streamlit.session_state.username}`")
        with col_key:
            streamlit.markdown(f"**Token de Sesión:** `{streamlit.session_state.session_token[:16]}...`")
        with col_logout:
            if streamlit.button("🚪 Cerrar Sesión", type = "secondary"):
                res = requests.post(f"{BASE_URL}/api/v1/logout", headers = {"X-Session-Token": streamlit.session_state.session_token})
                streamlit.session_state.authenticated = False
                streamlit.session_state.username = ""
                streamlit.session_state.session_token = ""
                streamlit.success("Sesión cerrada correctamente.")
                streamlit.rerun()

        streamlit.divider()

        # Pestañas principales de operación
        tab_tx, tab_audit = streamlit.tabs(["💸 Realizar Transferencia", "🛡️ Simulación de Ataques (Pruebas de Seguridad)"])


        # ------------------------------------------------------------
        #          PESTAÑA 1: TRANSFERENCIA BANCARIA LEGÍTIMA
        # ------------------------------------------------------------


        with tab_tx:
            streamlit.subheader("Formulario de Transacción Segura")
            col1, col2 = streamlit.columns(2)

            with col1:
                origin_acc = streamlit.text_input("Cuenta de Origen", value = "ES1122334455")
                dest_acc = streamlit.text_input("Cuenta Destino", value = "ES5544332211")
                amount = streamlit.number_input("Cantidad", min_value = 0.01, value = 150.00, step = 10.00)
                currency = streamlit.selectbox("Moneda", ["EUR", "USD", "GBP"])

            with col2:
                streamlit.info("Inspección Criptográfica en Tiempo Real")
                tx_id = str(uuid.uuid4())
                tx_payload = {
                    "txId": tx_id,
                    "origin_account": origin_acc,
                    "destination_account": dest_acc,
                    "amount": amount,
                    "currency": currency
                }
                body = json.dumps(tx_payload, separators = (',', ':'))

                nonce = secrets.token_hex(16)
                timestamp = str(time.time())
                payload = f"{body}|{nonce}|{timestamp}"
                signature = security.generate_mac(payload, bytes.fromhex(streamlit.session_state.session_token))

                streamlit.code(f"Payload JSON:\n{body}", language = "json")
                streamlit.text_input("X-Nonce (Generado)", value = nonce, disabled = True)
                streamlit.text_input("X-Timestamp (Generado)", value = timestamp, disabled = True)
                streamlit.text_input("X-Session-Token", value = streamlit.session_state.session_token, disabled = True)
                streamlit.text_input("X-Signature (HMAC-SHA256)", value = signature, disabled = True)

            if streamlit.button("🚀 Enviar Transferencia Protegida", type = "primary"):
                headers = {
                    "Content-Type": "application/json",
                    "username": streamlit.session_state.username,
                    "X-Nonce": nonce,
                    "X-Timestamp": timestamp,
                    "X-Signature": signature
                }

                response = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)

                if response.status_code == 200:
                    streamlit.balloons()
                    streamlit.success(f"✅ Transacción Aprobada (Status {response.status_code}): {response.json().get("message")}")
                else:
                    streamlit.error(f"❌ Transacción Rechazada (Status {response.status_code}): {response.json().get("detail")}")



        # --------------------------------------------------
        #          PESTAÑA 2: SIMULACIÓN DE ATAQUES
        # --------------------------------------------------


        with tab_audit:
            streamlit.subheader("Generador de Vulnerabilidades / Modos de Ataque")
            streamlit.write("Prueba de cómo reacciona el servidor ante manipulaciones de canal lateral, MitM o Replay.")

            attack_type = streamlit.radio(
                "Selecciona el vector de ataque a simular:",
                ["Ataque Man-in-the-Middle (Modificación de Monto)", "Ataque de Replay (Reutilizar Nonce)", "Expiración de Timestamp"]
            )

            if attack_type == "Ataque Man-in-the-Middle (Modificación de Monto)":
                streamlit.warning("Se firmará un monto de 100 EUR, pero se enviará un payload modificado de 10,000 EUR.")
                if streamlit.button("Ejecutar Ataque MitM"):

                    # Firma para 100 EUR
                    tx_orig = {
                        "txId": str(uuid.uuid4()),
                        "origin_account": "ES123456789",
                        "destination_account": "ES987654321",
                        "amount": 100.0,
                        "currency": "EUR"
                    }

                    body_orig = json.dumps(tx_orig, separators = (',', ':'))
                    n = secrets.token_hex(16)
                    ts = str(time.time())
                    pld = f"{body_orig}|{n}|{ts}"
                    sig = security.generate_mac(pld, bytes.fromhex(streamlit.session_state.session_token))

                    # Envío de 10,000 EUR con la firma anterior
                    tx_tampered = tx_orig.copy()
                    tx_tampered["amount"] = 10000.00
                    body_tampered = json.dumps(tx_tampered, separators = (',', ':'))

                    headers = {
                        "Content-Type": "application/json",
                        "username": streamlit.session_state.username,
                        "X-Nonce": n,
                        "X-Timestamp": ts,
                        "X-Signature": sig
                    }

                    res = requests.post(f"{BASE_URL}/api/v1/transfer", data = body_tampered, headers = headers)
                    
                    streamlit.code(f"Status: {res.status_code}\nRespuesta: {res.json().get("detail")}")
                    if res.status_code == 403:
                        streamlit.success("🛡️ SERVIDOR PROTEGIDO: Firma HMAC invalidada al detectar alteración de datos.")

            elif attack_type == "Ataque de Replay (Reutilizar Nonce)":
                streamlit.warning("Se enviará exactamente el mismo paquete de datos dos veces seguidas con el mismo Nonce.")
                if streamlit.button("Ejecutar Ataque Replay"):

                    tx = {
                        "txId": str(uuid.uuid4()),
                        "origin_account": "ES123456789",
                        "destination_account": "ES987654321",
                        "amount": 50.0,
                        "currency":"EUR"
                    }

                    body = json.dumps(tx, separators = (',', ':'))
                    n = secrets.token_hex(16)
                    ts = str(time.time())
                    pld = f"{body}|{n}|{ts}"
                    sig = security.generate_mac(pld, bytes.fromhex(streamlit.session_state.session_token))

                    headers = {
                        "Content-Type": "application/json",
                        "username": streamlit.session_state.username,
                        "X-Nonce": n,
                        "X-Timestamp": ts,
                        "X-Signature": sig
                    }
                    
                    # Envío 1
                    res1 = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
                    streamlit.info(f"Envío 1 (Legítimo): Status {res1.status_code}")
                    
                    # Envío 2 (Ataque Replay)
                    res2 = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)
                    streamlit.code(f"Envío 2 (Duplicado) Status: {res2.status_code}\nRespuesta: {res2.json().get("detail")}")
                    if res2.status_code == 400:
                        streamlit.success("🛡️ SERVIDOR PROTEGIDO: Nonce duplicado bloqueado exitosamente.")

            elif attack_type == "Expiración de Timestamp":
                streamlit.warning("Se enviará un paquete con un timestamp retrasado por más de 5 minutos.")
                if streamlit.button("Ejecutar Ataque Expiración"):

                    tx = {
                        "tx_id": str(uuid.uuid4()),
                        "origin_account": "ES123456789",
                        "destination_account": "ES987654321",
                        "amount": 50.0,
                        "currency": "EUR"
                    }

                    body = json.dumps(tx, separators = (',', ':'))
                    n = secrets.token_hex(16)
                    old_ts = str(time.time() - 400) # 400 segundos atrás
                    pld = f"{body}|{n}|{old_ts}"
                    sig = security.generate_mac(pld, bytes.fromhex(streamlit.session_state.session_token))

                    headers = {
                        "Content-Type": "application/json",
                        "username": streamlit.session_state.username,
                        "X-Nonce": n,
                        "X-Timestamp": old_ts,
                        "X-Signature": sig
                    }

                    res = requests.post(f"{BASE_URL}/api/v1/transfer", data = body, headers = headers)

                    streamlit.code(f"Status: {res.status_code}\nRespuesta: {res.json().get("detail")}")
                    if res.status_code == 400:
                        streamlit.success("🛡️ SERVIDOR PROTEGIDO: Paquete fuera de la ventana de tiempo rechazado.")


