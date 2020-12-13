from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64


class AES_CIPHER:
    BLOCK_SIZE_AES = 16  # AES: Bloque de 128 bits

    def __init__(self, key):
        """Inicializa las variables locales"""
        self.key = key

    def cifrar(self, cadena, iv, modo):
        if modo == AES.MODE_CBC:
            cipher = AES.new(self.key, modo, iv)
            ciphertext = cipher.encrypt(pad(cadena, type(self).BLOCK_SIZE_AES))
            
        elif modo == AES.MODE_ECB:
            cipher = AES.new(self.key, modo)
            ciphertext = cipher.encrypt(pad(cadena, type(self).BLOCK_SIZE_AES))
            
        elif modo == AES.MODE_CTR:
            counter = Counter.new(128, initial_value=0)
            cipher = AES.new(self.key, modo, counter=counter)
            ciphertext = cipher.encrypt(cadena)
            
        elif modo == AES.MODE_OFB:
            cipher = AES.new(self.key, modo, iv)
            ciphertext = cipher.encrypt(cadena)
            
        elif modo == AES.MODE_CFB:
            cipher = AES.new(self.key, modo, iv)
            ciphertext = cipher.encrypt(cadena)
            
        return ciphertext

    def descifrar(self, cifrado, iv, modo):
        if modo == AES.MODE_CBC:
            decipher_aes = AES.new(self.key, modo, iv)
            deciphertext = unpad(decipher_aes.decrypt(cifrado), type(self).BLOCK_SIZE_AES).decode("utf-8", "ignore")
            
        elif modo == AES.MODE_ECB:
            decipher_aes = AES.new(self.key, modo)
            deciphertext = unpad(decipher_aes.decrypt(cifrado), type(self).BLOCK_SIZE_AES).decode("utf-8", "ignore")
            
        elif modo == AES.MODE_CTR:
            counter = Counter.new(128, initial_value=0)
            decipher_aes = AES.new(self.key, modo, counter=counter)
            deciphertext = decipher_aes.decrypt(cifrado)
            
        elif modo == AES.MODE_OFB:
            decipher_aes = AES.new(self.key, modo, iv)
            deciphertext = decipher_aes.decrypt(cifrado)
            
        elif modo == AES.MODE_CFB:
            decipher_aes = AES.new(self.key, modo, iv)
            deciphertext = decipher_aes.decrypt(cifrado)
            
        return deciphertext


key = get_random_bytes(16)  # Clave aleatoria de 128 bits
IV = get_random_bytes(16)  # IV aleatorio de 128 bits
d = AES_CIPHER(key)

# AES-CBC
print("AES-CBC")
datos = "Hola Amigos de Seguridad".encode("utf-8")
print(datos)
cifrado = d.cifrar(datos, IV, AES.MODE_CBC)
print(base64.b64encode(cifrado))
descifrado = d.descifrar(cifrado, IV, AES.MODE_CBC)
print(descifrado)

# AES-ECB
print("AES-ECB")
datos = "Hola Amigos de Seguridad".encode("utf-8")
print(datos)
cifrado = d.cifrar(datos, IV, AES.MODE_ECB)
print(base64.b64encode(cifrado))
descifrado = d.descifrar(cifrado, IV, AES.MODE_ECB)
print(descifrado)

# AES-CTR
print("AES-CTR")
datos = "Hola Amigos de Seguridad".encode("utf-8")
print(datos)
cifrado = d.cifrar(datos, IV, AES.MODE_CTR)
print(base64.b64encode(cifrado))
descifrado = d.descifrar(cifrado, IV, AES.MODE_CTR)
print(descifrado)

# AES-OFB
print("AES-OFB")
datos = "Hola Amigos de Seguridad".encode("utf-8")
print(datos)
cifrado = d.cifrar(datos, IV, AES.MODE_OFB)
print(base64.b64encode(cifrado))
descifrado = d.descifrar(cifrado, IV, AES.MODE_OFB)
print(descifrado)

# AES-CFB
print("AES-CFB")
datos = "Hola Amigos de Seguridad".encode("utf-8")
print(datos)
cifrado = d.cifrar(datos, IV, AES.MODE_CFB)
print(base64.b64encode(cifrado))
descifrado = d.descifrar(cifrado, IV, AES.MODE_CFB)
print(descifrado)
