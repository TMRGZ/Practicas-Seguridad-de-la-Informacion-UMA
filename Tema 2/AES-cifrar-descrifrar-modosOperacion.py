from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64

key = get_random_bytes(16)
IV = get_random_bytes(16)
BLOCK_SIZE = 16

cipher = AES.new(key, AES.MODE_CBC, IV)
data = "Hola mundo nuevo con CBC".encode("utf-8")
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))
print(ciphertext)
encoded = base64.b64encode(ciphertext)
print(encoded)

decipher_aes = AES.new(key, AES.MODE_CBC, IV)
print(unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE).decode("utf-8", "ignore"))
print("#---------------------------")
# ---------------------------

cipher = AES.new(key, AES.MODE_ECB)
data = "Hola mundo nuevo con ECB".encode("utf-8")
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))
print(ciphertext)
encoded = base64.b64encode(ciphertext)
print(encoded)

decipher_aes = AES.new(key, AES.MODE_ECB)
print(unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE).decode("utf-8", "ignore"))
print("#---------------------------")

# ---------------------------

iv = get_random_bytes(8)
countf = Counter.new(64, iv)

cipher = AES.new(key, AES.MODE_CTR, counter=countf)
data = "Hola mundo nuevo con CTR".encode("utf-8")
ciphertext = cipher.encrypt(pad(data, BLOCK_SIZE))
print(ciphertext)
encoded = base64.b64encode(ciphertext)
print(encoded)

decipher_aes = AES.new(key, AES.MODE_CTR, counter=countf)
print(unpad(decipher_aes.decrypt(ciphertext), BLOCK_SIZE).decode("utf-8", "ignore"))
print("#---------------------------")

# ---------------------------
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CFB, nonce)
data = "Hola mundo nuevo con CFB".encode("utf-8")
ciphertext = cipher.encrypt(data)
print(ciphertext)
encoded = base64.b64encode(ciphertext)
print(encoded)

decipher_aes = AES.new(key, AES.MODE_CFB, nonce)
print(decipher_aes.decrypt(ciphertext).decode("utf-8", "ignore"))
print("#---------------------------")

# ---------------------------
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = "Hola mundo nuevo con EAX".encode("utf-8")
ciphertext = cipher.encrypt(data)
print(ciphertext)
encoded = base64.b64encode(ciphertext)
print(encoded)

decipher_aes = AES.new(key, AES.MODE_EAX, nonce)
print(decipher_aes.decrypt(ciphertext).decode("utf-8", "ignore"))
print("#---------------------------")
