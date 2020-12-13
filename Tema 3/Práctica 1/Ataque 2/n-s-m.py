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
# Copio clave
fileIn = open("key", "r")
t_bt = fileIn.read()
fileIn.close()
# Consigo K_AB
decipher_aes_b_t = AES.new(key_b_t, AES.MODE_ECB)
json_a_b = unpad(decipher_aes_b_t.decrypt(bytearray.fromhex(t_bt)), BLOCK_SIZE_AES).decode("utf-8")
print("Hijack, A->B (Clear): " + json_a_b)
msg_a_b = json.loads(json_a_b)
a_key_a_b, a_alice = msg_a_b
a_key_a_b = bytearray.fromhex(a_key_a_b)

#####################################################################
# PROCESO DE ATAQUE
#####################################################################
print("Conecto a Bob")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 6666)
socket.conectar()
# Conectado
# Paso 3
socket.enviar(bytearray.fromhex(t_bt))
print("M->B: " + t_bt)
# Paso 4
datos = socket.recibir()
decipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
json_b_a = (unpad(decipher_aes_a_b.decrypt(datos), BLOCK_SIZE_AES).decode("utf-8"))
print("B->M (Clear): " + json_b_a)
msg_b_a = json.loads(json_b_a)
b_random = bytearray.fromhex(msg_b_a)
b_random = int(b_random.hex(), 16) - 1
b_random = hex(b_random)[2:]
json_a_b = json.dumps(b_random)
cipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
datos = cipher_aes_a_b.encrypt(pad(json_a_b.encode("utf-8"), BLOCK_SIZE_AES))
print("M->B (Clear): " + json_a_b)
socket.enviar(datos)

# Canal seguro
nombre = "Yo Mallory"
cipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
decipher_aes_a_b = AES.new(a_key_a_b, AES.MODE_ECB)
# Recibir nombre
datos = socket.recibir()
json_nombre = unpad(decipher_aes_a_b.decrypt(datos), BLOCK_SIZE_AES).decode("utf-8")
print("B->M (Clear): " + json_nombre)
# Enviar nombre
json_nombre = json.dumps(nombre)
datos = cipher_aes_a_b.encrypt(pad(json_nombre.encode("utf-8"), BLOCK_SIZE_AES))
print("M->B (Clear): " + json_nombre)
socket.enviar(datos)
socket.cerrar()

