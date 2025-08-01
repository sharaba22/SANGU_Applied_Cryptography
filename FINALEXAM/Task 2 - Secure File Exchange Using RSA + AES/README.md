# Secure File Exchange using RSA + AES

## Flow Summary

1. **Bob generates RSA key pair** – `private.pem`, `public.pem`
2. **Alice writes a message** – `alice_message.txt`
3. **Alice generates AES-256 key & IV**
4. **Alice encrypts her message with AES**, saves as `encrypted_file.bin`
5. **Alice encrypts the AES key with Bob's RSA public key**, saves as `aes_key_encrypted.bin`
6. **Bob decrypts AES key using his private key**
7. **Bob decrypts the file with AES key + IV**, recovers `decrypted_message.txt`
8. **SHA-256 hash** of the original and decrypted files are compared for **integrity**

## AES vs RSA Comparison

| Feature      | AES (Symmetric)                     | RSA (Asymmetric)                        |
|--------------|-------------------------------------|-----------------------------------------|
| Speed        | Very fast (suitable for large data) | Slower (suitable for small data only)   |
| Key Length   | 256-bit                             | 2048-bit (commonly used)                |
| Use Case     | File encryption, disk encryption    | Secure key exchange, digital signatures |
| Security     | Strong, efficient                   | Strong but slower and heavier           |

Hybrid encryption combines both: **RSA for secure key exchange**, **AES for fast file encryption**.

## Files in This Project

- `alice_message.txt`: Original message
- `encrypted_file.bin`: AES-encrypted message
- `aes_key_encrypted.bin`: AES key encrypted with RSA
- `decrypted_message.txt`: Decrypted file by Bob
- `public.pem`, `private.pem`: Bob’s RSA key pair
- `secure_file_exchange.py`: Script
- `README.md`: Documentation

## Integrity Verification

The program computes and compares the SHA-256 hash of the original and decrypted message. If they match, the file was decrypted correctly without tampering.

