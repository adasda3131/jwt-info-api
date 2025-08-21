from flask import Flask, request, jsonify
import os
import httpx # httpx funciona tanto para sync quanto para async
# asyncio não é mais necessário
import json
import base64
from typing import Tuple
from google.protobuf import json_format
from google.protobuf.message import Message
from Crypto.Cipher import AES

import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

# <<< MUDANÇA: Inicialização do Flask
app = Flask(__name__)

# --- Constantes (permanecem as mesmas) ---
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==') # Equivalente a "Yg&tc%DEuh6%Zc^8"
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')    # Equivalente a "6oyZDr22E3ychjM%"

RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"


# --- Funções auxiliares (a maioria permanece igual) ---
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

# <<< MUDANÇA: A função não precisa mais ser 'async'
def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(encoded_data: bytes, message_type: Message) -> Message:
    message_instance = message_type()
    message_instance.ParseFromString(encoded_data)
    return message_instance


# --- Funções principais (convertidas para síncronas) ---

# <<< MUDANÇA: Função agora é síncrona (sem 'async')
def get_access_token(uid: str, password: str) -> Tuple[str, str, int]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    
    try:
        print("--- DEBUG: 2. Chamando get_access_token para o servidor da Garena...")
        # <<< MUDANÇA: Usando o cliente síncrono httpx.Client
        with httpx.Client(timeout=10.0) as client:
            # <<< MUDANÇA: Sem 'await'
            response = client.post(url, data=payload, headers=headers)
            print("--- DEBUG: 3. Servidor da Garena respondeu.")
            if response.status_code == 200:
                data = response.json()
                return data.get("access_token", "0"), data.get("open_id", "0"), 200
            return "0", "0", response.status_code
    except httpx.RequestError as e:
        print(f"--- DEBUG: ERRO na requisição httpx: {e}")
        return "0", "0", 500


# <<< MUDANÇA: Função agora é síncrona (sem 'async')
def create_jwt(uid: str, password: str) -> Tuple[str, str, int]:
    # <<< MUDANÇA: Sem 'await'
    access_token, open_id, status_code = get_access_token(uid, password)

    if status_code != 200:
        return "0", "0", status_code

    json_data = json.dumps({
      "open_id": open_id,
      "open_id_type": "4",
      "login_token": access_token,
      "orign_platform_type": "4"
    })
    # <<< MUDANÇA: Sem 'await'
    encoded_result = json_to_proto(json_data, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Expect': '100-continue',
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': 'v1 1',
        'ReleaseVersion': RELEASEVERSION,
        'Content-Type': 'application/octet-stream',
        'Accept-Encoding': 'gzip'
    }

    try:
        # <<< MUDANÇA: Usando o cliente síncrono httpx.Client
        with httpx.Client(timeout=10.0) as client:
            # <<< MUDANÇA: Sem 'await'
            response = client.post(url, data=payload, headers=headers)
            
            if response.status_code != 200:
                return "0", access_token, response.status_code

            response_content = response.content
            try:
                message = json.loads(json_format.MessageToJson(
                    decode_protobuf(response_content, FreeFire_pb2.LoginRes)
                ))
                token = message.get("token", "0")
                return token, access_token, 200
            except Exception:
                return "0", access_token, 500
    except httpx.RequestError:
        return "0", access_token, 500


# --- Rota da API (estilo Flask) ---
# <<< MUDANÇA: Usando @app.route do Flask e definindo o método GET
@app.route("/create_jwt", methods=['GET'])
def generate_jwt():
    # <<< MUDANÇA: Acessando parâmetros de query com request.args.get()
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"status": "error", "message": "Parâmetros 'uid' e 'password' são obrigatórios."}), 400

    print("--- DEBUG: 1. Rota /create_jwt foi chamada.")
    # <<< MUDANÇA: Sem 'await'
    token, access_token, status_code = create_jwt(uid, password)
    
    response_data = {
        "token": token,
        "token_access": access_token
    }

    if status_code == 200 and token != "0":
        response_data["status"] = "live"
    else:
        response_data["status"] = f"error_{status_code}"

    print(f"--- DEBUG: 4. Retornando resposta: {response_data}")
    # <<< MUDANÇA: Usando jsonify para retornar a resposta em JSON
    return jsonify(response_data)


# <<< MUDANÇA: Adicionando rota raiz para health checks do Railway
@app.route("/")
def health_check():
    return jsonify({"status": "ok"})


# <<< MUDANÇA: Bloco de execução padrão do Flask
if __name__ == "__main__":
    # Pega a porta do ambiente do Railway, ou usa 5552 como padrão
    port = int(os.environ.get("PORT", 5552))
    # Inicia o servidor de desenvolvimento do Flask
    app.run(host="0.0.0.0", port=port)
