from socket_class import SOCKET_SIMPLE_TCP
from rsa_class import RSA_OBJECT
from aes_class import AES_CIPHER
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import json

# Recibe la informacion del vendedor
####################################
# Crea el socket en 5556
print("Creando socket y escuchando...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5556)
socket.escuchar()

# Recibe los datos y cierra el socket
datos = socket.recibir()
json_banco = datos.decode("utf-8", "ignore")
socket.cerrar()

# Decodifica los datos
msg_vendedor = json.loads(json_banco)
json_banco_cifrado_hex, IV_banco_hex, digital_envelope_hex, pub_usuario_hex = msg_vendedor

# Extrae la informacion del digital envelope
############################################
json_banco_cifrado = bytearray.fromhex(json_banco_cifrado_hex)
IV_banco = bytes.fromhex(IV_banco_hex)
digital_envelope = bytes.fromhex(digital_envelope_hex)

RSA_Banco = RSA_OBJECT()
RSA_Banco.load_PrivateKey("rsa_key.pem", "password")
k = RSA_Banco.decrypt(digital_envelope)

AES_Usuario = AES_CIPHER(k)
json_banco = AES_Usuario.decrypt(json_banco_cifrado, IV_banco)

msg_usuario = json.loads(json_banco)
PI_banco, firma_dual_hex, OIMD_hex = msg_usuario

#####################################################
# A REALIZAR POR EL ALUMNO
#
# Comprobar que la informacion recibida por parte 
# del vendedor es integra, considerando en este caso
# la firma dual computada por el cliente
######################################################


PIMD = SHA256.new(PI_banco.encode("utf-8", "ignore")).digest()
POMD = SHA256.new(bytearray.fromhex(OIMD_hex) + PIMD).digest()

RSA = RSA_OBJECT()
RSA.set_PublicKeyPEM(bytearray.fromhex(pub_usuario_hex))

firma_dual = bytearray.fromhex(firma_dual_hex)

######################################################

if RSA.verify(firma_dual, POMD):  # a terminar también por el alumno ...
    print("firma dual invalida")
    exit()

# Prepara el genero para la venta :-)
print("BANCO: " + PI_banco)

# Termina
print("Banco finalizado correctamente")
