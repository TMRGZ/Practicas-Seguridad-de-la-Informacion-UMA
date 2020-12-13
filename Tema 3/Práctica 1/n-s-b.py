from Crypto.Cipher import PKCS1_OAEP, DES, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json
from socket_class import SOCKET_SIMPLE_TCP

# Parametros
BLOCK_SIZE_AES = 16
key_b_t = b'FEDCBA9876543210'

# Crea el socket servidor y escucha
print("Creando socket y escuchando...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 6666)
socket.escuchar()

# A->B: E_BT(K_AB, Alice)
datos = socket.recibir()
# datos = bytearray.fromhex(datos)
decipher_aes_b_t = AES.new(key_b_t, AES.MODE_ECB)
json_a_b = unpad(decipher_aes_b_t.decrypt(datos), BLOCK_SIZE_AES).decode("utf-8")
print("A->B (Clear): " + json_a_b)
msg_a_b = json.loads(json_a_b)

# T: Stores K_AB, Alice; creates random Rb
a_key_a_b, a_alice = msg_a_b
a_key_a_b = bytearray.fromhex(a_key_a_b)
b_random = get_random_bytes(8)

# B->A: E_BA(Rb)
msg_b_a = b_random.hex()
json_b_a = json.dumps(msg_b_a)
cipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
datos = cipher_aes_a_b.encrypt(pad(json_b_a.encode("utf-8"), BLOCK_SIZE_AES))
print("B->A (Clear): " + json_b_a)
socket.enviar(datos)

# A->B: E_BA(Rb-1)
datos = socket.recibir()
decipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
json_a_b = unpad(decipher_aes_a_b.decrypt(datos), BLOCK_SIZE_AES).decode("utf-8")
print("A->B (Clear): " + json_a_b)
msg_a_b = json.loads(json_a_b)

# Comprobar
b_random_1 = msg_a_b
# Pasar a int
b_random = int(b_random.hex(), 16) - 1
b_random = hex(b_random)[2:]

if b_random_1 == b_random:
    print("Canal seguro establecido")
    nombre = "Yo soy Bob"
    cipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
    decipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
    # Enviar nombre
    json_nombre = json.dumps(nombre)
    datos = cipher_aes_a_b.encrypt(pad(json_nombre.encode("utf-8"), BLOCK_SIZE_AES))
    print("B->A (Clear): " + json_nombre)
    socket.enviar(datos)
    # Recibir nombre
    datos = socket.recibir()
    json_nombre = unpad(decipher_aes_a_b.decrypt(datos), BLOCK_SIZE_AES).decode("utf-8")
    print("A->B (Clear): " + json_nombre)
    socket.cerrar()
else:
    print("No bueno")
    print(b_random)
    print(b_random_1)
    socket.cerrar()
