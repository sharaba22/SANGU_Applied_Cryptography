from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
import os


# Step 1: Generate RSA key pair for Bob
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)


# Step 2: Create Alice's message
def create_alice_message():
    with open("alice_message.txt", "w") as f:
        f.write("This is a top secret file sent securely from Alice to Bob.")


# Step 3-4: Generate AES key/IV and encrypt file
def encrypt_file_with_aes():
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)

    with open("alice_message.txt", "rb") as f:
        plaintext = f.read()

    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)

    with open("encrypted_file.bin", "wb") as f:
        f.write(iv + ciphertext)

    return key, iv


# Step 5: Encrypt AES key with RSA
def encrypt_aes_key_rsa(aes_key):
    with open("public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_key)


# Step 6: Decrypt AES key with RSA
def decrypt_aes_key_rsa():
    with open("private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    with open("aes_key_encrypted.bin", "rb") as f:
        encrypted_key = f.read()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key


# Step 7: Decrypt file using AES key and IV
def decrypt_file_with_aes(aes_key):
    with open("encrypted_file.bin", "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext)

    with open("decrypted_message.txt", "wb") as f:
        f.write(plaintext)


# Step 8: Verify file integrity
def sha256_digest(file_path):
    digest = hashes.Hash(hashes.SHA256())
    with open(file_path, "rb") as f:
        data = f.read()
        digest.update(data)
    return digest.finalize()


# Run full workflow
if __name__ == "__main__":
    generate_rsa_keys()
    create_alice_message()
    aes_key, iv = encrypt_file_with_aes()
    encrypt_aes_key_rsa(aes_key)

    # Bob decrypts the AES key and message
    decrypted_key = decrypt_aes_key_rsa()
    decrypt_file_with_aes(decrypted_key)

    # Hash comparison
    original_hash = sha256_digest("alice_message.txt")
    final_hash = sha256_digest("decrypted_message.txt")

    print("Original SHA-256:", original_hash.hex())
    print("Decrypted SHA-256:", final_hash.hex())
    print("Integrity Check:", "Passed" if original_hash == final_hash else "Failed")