from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad


class RSA_OBJECT:
    def __init__(self):
        """Inicializa un objeto RSA, sin ninguna clave"""
        # Nota: Para comprobar si un objeto (no) ha sido inicializado, hay
        #   que hacer "if self.public_key is None:"
        self.private_key = None

    def create_KeyPair(self):
        """Crea un par de claves publico/privada, y las almacena dentro de la instancia"""
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def save_PrivateKey(self, file, password):
        """Guarda la clave privada self.private_key en un fichero file, usando una contraseña password"""
        fileOut = open(file, "wb")
        fileOut.write(self.private_key.export_key(
            passphrase=password, pkcs=8, protection="scryptAndAES128-CBC"))
        fileOut.close()

    def load_PrivateKey(self, file, password):
        """Carga la clave privada self.private_key de un fichero file, usando una contraseña password"""
        encoded_key = open(file, "rb").read()
        self.private_key = RSA.import_key(encoded_key, passphrase=password)

    def save_PublicKey(self, file):
        """Guarda la clave publica self.public_key en un fichero file"""
        fileOut = open(file, "wb")
        fileOut.write(self.public_key.export_key())
        fileOut.close()

    def load_PublicKey(self, file):
        """Carga la clave publica self.public_key de un fichero file"""
        fileKey = open(file, "rb").read()
        self.public_key = RSA.import_key(fileKey)

    def cifrar(self, datos):
        """Cifra el parámetro datos (de tipo binario) con la clave self.public_key, y devuelve
           el resultado. En caso de error, se devuelve None"""
        cif = PKCS1_OAEP.new(self.public_key)
        return cif.encrypt(datos)

    def descifrar(self, cifrado):
        """Descrifra el parámetro cifrado (de tipo binario) con la clave self.private_key, y devuelve
           el resultado (de tipo binario). En caso de error, se devuelve None"""
        desc = PKCS1_OAEP.new(self.private_key)
        return desc.decrypt(cifrado)

    def firmar(self, datos):
        """Firma el parámetro datos (de tipo binario) con la clave self.private_key, y devuelve el 
           resultado. En caso de error, se devuelve None."""
        h = SHA256.new(datos)
        return pss.new(self.private_key).sign(h)

    def comprobar(self, text, signature):
        """Comprueba el parámetro text (de tipo binario) con respecto a una firma signature 
           (de tipo binario), usando para ello la clave self.public_key. 
           Devuelve True si la comprobacion es correcta, o False en caso contrario o 
           en caso de error."""
        h = SHA256.new(text)
        verifier = pss.new(self.public_key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


class AES_CIPHER:
    BLOCK_SIZE_AES = 16  # AES: Bloque de 128 bits

    def __init__(self, key):
        self.key = key

    def cifrar(self, cadena):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(cadena, type(self).BLOCK_SIZE_AES))

    def descifrar(self, cifrado):
        decipher_aes = AES.new(self.key, AES.MODE_ECB)
        return unpad(decipher_aes.decrypt(cifrado), type(self).BLOCK_SIZE_AES).decode("utf-8", "ignore")


print("Ejercicio 1")
# Main
# Crear clave RSA
# y guardar en ficheros la clave privada (protegida) y publica
password = "password"
private_file = "rsa_key.pem"
public_file = "rsa_key.pub"
RSA_key_creator = RSA_OBJECT()
RSA_key_creator.create_KeyPair()
RSA_key_creator.save_PrivateKey(private_file, password)
RSA_key_creator.save_PublicKey(public_file)
# Crea dos clases, una con la clave privada y otra con la clave publica
RSA_private = RSA_OBJECT()
RSA_public = RSA_OBJECT()
RSA_private.load_PrivateKey(private_file, password)
RSA_public.load_PublicKey(public_file)
# Cifrar y Descifrar con PKCS1 OAEP
cadena = "Lo desconocido es lo contrario de lo conocido. Pasalo."
cifrado = RSA_public.cifrar(cadena.encode("utf-8"))
print(cifrado)
descifrado = RSA_private.descifrar(cifrado).decode("utf-8")
print(descifrado)
# Firmar y comprobar con PKCS PSS
firma = RSA_private.firmar(cadena.encode("utf-8"))
if RSA_public.comprobar(cadena.encode("utf-8"), firma):
    print("La firma es valida")
else:
    print("La firma es invalida")

print("Ejercicio 2a")
# Constantes
passwordA = "contra"
passwordB = "senna"
private_file_A = "privateA.pem"
public_file_A = "publicA.pub"
private_file_B = "privateB.pem"
public_file_B = "publicB.pub"
# Creacion y guardado
RSA_creator = RSA_OBJECT()
# A
RSA_creator.create_KeyPair()
RSA_creator.save_PrivateKey(private_file_A, passwordA)
RSA_creator.save_PublicKey(public_file_A)
# B
RSA_creator.create_KeyPair()
RSA_creator.save_PrivateKey(private_file_B, passwordB)
RSA_creator.save_PublicKey(public_file_B)
# Cargar claves
privada_a = RSA_OBJECT()
publica_a = RSA_OBJECT()
privada_b = RSA_OBJECT()
publica_b = RSA_OBJECT()
# A
privada_a.load_PrivateKey(private_file_A, passwordA)
publica_a.load_PublicKey(public_file_A)
# B
privada_b.load_PrivateKey(private_file_B, passwordB)
publica_b.load_PublicKey(public_file_B)
# Procedimiento
cadena = "Hola amigos de seguridad"
# I
c = publica_b.cifrar(cadena.encode("utf-8"))
print(c)
# II
s = privada_a.firmar(c)
# III
# Guardo c y s
fileOut = open("archivoC", "wb")
fileOut.write(c)
fileOut.close()
fileOut = open("archivoS", "wb")
fileOut.write(s)
fileOut.close()
# Cargo c y s
fileIn = open("archivoC", "rb")
c = fileIn.read()
fileIn.close()
fileIn = open("archivoS", "rb")
s = fileIn.read()
fileIn.close()
# IV
if publica_a.comprobar(c, s):
    mensaje = privada_b.descifrar(c)
    print(mensaje)
else:
    print("Error")

print("Ejercicio 2b")
# Preparar AES
key = get_random_bytes(16)  # Clave aleatoria de 128 bits
d = AES_CIPHER(key)
cadena = "Hola amigos de seguridad".encode("utf-8")
fileOut = open("cifrado", "wb")
cif = d.cifrar(cadena)
print(cif)
fileOut.write(cif)
fileOut.close()

# Constantes
passwordA = "contra"
passwordB = "senna"
private_file_A = "privateA.pem"
public_file_A = "publicA.pub"
private_file_B = "privateB.pem"
public_file_B = "publicB.pub"
# Creacion y guardado
RSA_creator = RSA_OBJECT()
# A
RSA_creator.create_KeyPair()
RSA_creator.save_PrivateKey(private_file_A, passwordA)
RSA_creator.save_PublicKey(public_file_A)
# B
RSA_creator.create_KeyPair()
RSA_creator.save_PrivateKey(private_file_B, passwordB)
RSA_creator.save_PublicKey(public_file_B)
# Cargar claves
privada_a = RSA_OBJECT()
publica_a = RSA_OBJECT()
privada_b = RSA_OBJECT()
publica_b = RSA_OBJECT()
# A
privada_a.load_PrivateKey(private_file_A, passwordA)
publica_a.load_PublicKey(public_file_A)
# B
privada_b.load_PrivateKey(private_file_B, passwordB)
publica_b.load_PublicKey(public_file_B)
# Procedimiento
# I
c = publica_b.cifrar(key)
# II
s = privada_a.firmar(c)
# III
# Guardo c y s
fileOut = open("archivoCAES", "wb")
fileOut.write(c)
fileOut.close()
fileOut = open("archivoSAES", "wb")
fileOut.write(s)
fileOut.close()
# Cargo c y s
fileIn = open("archivoCAES", "rb")
c = fileIn.read()
fileIn.close()
fileIn = open("archivoSAES", "rb")
s = fileIn.read()
fileIn.close()
# IV
if publica_a.comprobar(c, s):
    key = privada_b.descifrar(c)
else:
    print("Error")

fileIn = open("cifrado", "rb")
cifrado = fileIn.read()
fileIn.close()
des = AES_CIPHER(key)
print(des.descifrar(cifrado))
# La diferencia de tamaño entre un AES y un RSA es enorme respecto al AES, siendo este el mas pequeño



