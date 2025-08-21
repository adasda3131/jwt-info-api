import uvicorn
import os

from fastapi import FastAPI, Query
import httpx
import asyncio
import json
import base64
from typing import Tuple
from google.protobuf import json_format
from google.protobuf.message import Message
from Crypto.Cipher import AES

import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

app = FastAPI()

# --- Constantes alinhadas com o código que funciona ---
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==') # Equivalente a "Yg&tc%DEuh6%Zc^8"
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')    # Equivalente a "6oyZDr22E3ychjM%"

RELEASEVERSION = "OB50"
# ATUALIZADO: User-Agent idêntico ao do código Flask para máxima consistência.
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"


# --- Funções auxiliares ---
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(encoded_data: bytes, message_type: Message) -> Message:
    message_instance = message_type()
    message_instance.ParseFromString(encoded_data)
    return message_instance


# --- Funções principais ---
async def get_access_token(uid: str, password: str) -> Tuple[str, str, int]:
    # --- ESTAS LINHAS PRECISAM ESTAR AQUI ---
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    # ----------------------------------------
    
    try:
        print("--- DEBUG: 2. Chamando get_access_token para o servidor da Garena...")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, data=payload, headers=headers)
            print("--- DEBUG: 3. Servidor da Garena respondeu.")
            if response.status_code == 200:
                data = response.json()
                return data.get("access_token", "0"), data.get("open_id", "0"), 200
            return "0", "0", response.status_code
    except httpx.RequestError as e:
        print(f"--- DEBUG: ERRO na requisição httpx: {e}")
        return "0", "0", 500


async def create_jwt(uid: str, password: str) -> Tuple[str, str, int]:
    access_token, open_id, status_code = await get_access_token(uid, password)

    if status_code != 200:
        return "0", "0", status_code

    json_data = json.dumps({
      "open_id": open_id,
      "open_id_type": "4",
      "login_token": access_token,
      "orign_platform_type": "4"
    })
    encoded_result = await json_to_proto(json_data, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)

    url = "https://loginbp.ggblueshark.com/MajorLogin" # Mantendo o endpoint original
    
    # ATUALIZADO: Headers agora espelham a estrutura do código que funciona.
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Expect': '100-continue', # <--- ADICIONADO para espelhar o código Flask
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': 'v1 1', # <--- A MUDANÇA MAIS IMPORTANTE. Usando o X-GA simples que funciona.
        'ReleaseVersion': RELEASEVERSION,
        'Content-Type': 'application/octet-stream', # Mantido, pois é o tipo de conteúdo correto para este payload
        'Accept-Encoding': 'gzip'
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, data=payload, headers=headers)
            
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


# --- Rota da API ---
@app.get("/create_jwt")
async def generate_jwt(uid: str = Query(..., description="User ID"), password: str = Query(..., description="User Password")):
    print("--- DEBUG: 1. Rota /create_jwt foi chamada.")
    token, access_token, status_code = await create_jwt(uid, password)
    
    response_data = {
        "token": token,
        "token_access": access_token
    }

    if status_code == 200 and token != "0":
        response_data["status"] = "live"
    else:
        response_data["status"] = f"error_{status_code}"

    print(f"--- DEBUG: 4. Retornando resposta: {response_data}")
    return response_data

# --- Bloco para iniciar o servidor ---
# Este bloco será executado apenas quando você rodar o script diretamente (ex: python app.py)
if __name__ == "__main__":
    # O Railway define a variável de ambiente 'PORT'. Usamos ela se estiver disponível.
    # Caso contrário (rodando localmente), usamos a porta 8000 como padrão.
    port = int(os.environ.get("PORT", 8000))
    
    # Inicia o servidor Uvicorn.
    # host="0.0.0.0" é crucial para que a aplicação seja acessível dentro de contêineres (como no Railway).
    # Para produção, você pode remover o 'reload=True'.
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
