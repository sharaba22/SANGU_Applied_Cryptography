from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

# Step 1: User A generates RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save and load RSA keys
def save_rsa_keys(private_key, public_key):
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key():
    with open("public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Step 2: AES encryption
def encrypt_message_with_aes(message, aes_key, iv):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

# Step 3: RSA encryption of AES key
def encrypt_aes_key_with_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# Step 4: Decryption
def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_message_with_aes(encrypted_data, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

# MAIN FLOW
# Generate RSA keys for User A
private_key, public_key = generate_rsa_keys()
save_rsa_keys(private_key, public_key)

# User B encrypts message
with open("message.txt", "w") as f:
    f.write("This is a secret message from User B to User A.")

message = open("message.txt").read()
aes_key = os.urandom(32)  # AES-256
iv = os.urandom(16)

encrypted_message = encrypt_message_with_aes(message, aes_key, iv)
with open("encrypted_message.bin", "wb") as f:
    f.write(iv + encrypted_message)

public_key_loaded = load_public_key()
encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key_loaded)
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# User A decrypts message
private_key_loaded = load_private_key()
encrypted_aes_key = open("aes_key_encrypted.bin", "rb").read()
aes_key_decrypted = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_loaded)

data = open("encrypted_message.bin", "rb").read()
iv = data[:16]
ciphertext = data[16:]

decrypted_message = decrypt_message_with_aes(ciphertext, aes_key_decrypted, iv)

with open("decrypted_message.txt", "w") as f:
    f.write(decrypted_message)

print("Encryption and decryption successful.")