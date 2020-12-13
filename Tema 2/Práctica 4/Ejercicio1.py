from Crypto.Hash import SHA512, HMAC, SHA3_256

print("Ejercicio 1a")
# Abrir fichero
fileIn = open("Ejercicio1.txt", "r")
buf = fileIn.read().encode("utf-8")
fileIn.close()
# Hacer hash
h = SHA512.new()
h.update(buf)
print(h.hexdigest())

print("Ejercicio 1b")
# Preparar cosas
key = b'S3cr3tK3y'
# Leer fichero
fileIn = open("Ejercicio1.txt", "r")
buf = fileIn.read().encode("utf-8")
fileIn.close()
# Hacer HMAC-SHA512
h1 = HMAC.new(key, digestmod=SHA512)
h1.update(buf)
print(h1.hexdigest())
# Comprobar
h2 = HMAC.new(key, digestmod=SHA512)
h2.update(buf)
try:
    h2.hexverify(h1.hexdigest())
    print("Mensaje bueno")
except ValueError:
    print("Mensaje no bueno")

print("Ejercicio 1c")
# Preparacion
BLOCKSIZE = 4096
# Crear hash
h = SHA3_256.new()
# Proceder
with open("Ejercicio1c.docx", "rb") as fileIn:
    buf = fileIn.read(BLOCKSIZE)
    while len(buf) > 0:
        h.update(buf)
        buf = fileIn.read(BLOCKSIZE)
    fileIn.close()
print(h.hexdigest())

print("Ejercicio 2")
# Preparar cosas
key = b'S3cr3tK3y'
# Hacer SHA3-256
h1 = HMAC.new(key, digestmod=SHA3_256)

try:
    h2.hexverify(h1.hexdigest())
    print("Mensaje bueno")
except ValueError:
    print("Mensaje no bueno")

# Hash no compatibles con HMAC SHA3-256 no tiene un atributo block_size El atributo block_size solo se encuentra en
# algoritmos basados en Merkle-Damgard que dejó de ser usado en SHA3 por ser bombardeable por CPUs cuanticas
