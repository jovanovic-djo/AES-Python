import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(key, message, key_size):
    backend = default_backend()
    key = hashlib.sha256(key.encode()).digest()[:key_size//8]  # Derive key from input
    iv = bytes(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    message = message.encode()
    pad = 16 - (len(message) % 16)
    message = message + bytes([pad] * pad)  # Pad the message
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return base64.b64encode(encrypted_message).decode()

def decrypt(key, encrypted_message, key_size):
    backend = default_backend()
    key = hashlib.sha256(key.encode()).digest()[:key_size//8]  # Derive key from input
    try:
        encrypted_message = base64.b64decode(encrypted_message.encode())
    except:
        return "Error: Invalid base64 encoded message"
    iv = bytes(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    if decrypted_message[-1] > 16:
        return "Error: Invalid padding"
    decrypted_message = decrypted_message[:-decrypted_message[-1]]  # Unpad the message
    return decrypted_message.decode()

mode = input("Enter mode (encrypt(e)/decrypt(d)): ")
message = input("Enter message: ")
key = input("Enter key: ")
key_size = input("Enter key size (128, 192, or 256): ")

try:
    key_size = int(key_size)
    if key_size not in [128, 192, 256]:
        raise Exception
except:
    print("Error: Invalid key size")
    exit()

if mode.lower() == 'e':
    result = encrypt(key, message, key_size)
    print("Encrypted message: ", result)
elif mode.lower() == 'e':
    result = decrypt(key, message, key_size)
    if "Error:" in result:
        print(result)
    else:
        print("Decrypted message: ", result)
else:
    print("Error: Invalid mode")
