from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64


class DES_CIPHER:
    BLOCK_SIZE_DES = 8  # DES: Bloque de 64 bits

    def __init__(self, key):
        """Inicializa las variables locales"""
        self.key = key

    def cifrar(self, cadena, IV):
        """Cifra el parámetro cadena (de tipo String) con una IV específica, y
           devuelve el texto cifrado binario"""
        cipher = DES.new(self.key, DES.MODE_CBC, IV)
        ciphertext = cipher.encrypt(pad(cadena, type(self).BLOCK_SIZE_DES))
        return ciphertext

    def descifrar(self, cifrado, IV):
        """Descrifra el parámetro cifrado (de tipo binario) con una IV específica, y
           devuelve la cadena en claro de tipo String"""
        decipher_des = DES.new(self.key, DES.MODE_CBC, IV)
        return unpad(decipher_des.decrypt(cifrado), type(self).BLOCK_SIZE_DES).decode("utf-8", "ignore")


key = get_random_bytes(8)  # Clave aleatoria de 64 bits
IV = get_random_bytes(8)  # IV aleatorio de 64 bits
datos = "Hola Mundo con DES en modo CBC".encode("utf-8")
print(datos)
d = DES_CIPHER(key)
cifrado = d.cifrar(datos, IV)
print(base64.b64encode(cifrado))
descifrado = d.descifrar(cifrado, IV)
print(descifrado)

