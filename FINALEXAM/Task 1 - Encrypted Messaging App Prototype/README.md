# Encrypted Messaging App - Encryption Flow

## Overview
This application simulates a secure communication system using both RSA and AES encryption. The goal is to ensure confidentiality by combining the strengths of both algorithms.

## Step-by-Step Encryption Flow

### 1. RSA Key Generation (User A)
- User A generates a 2048-bit RSA key pair.
- The public key is shared with User B.
- The private key remains confidential.

### 2. Message Encryption by User B
- User B creates a secret message (`message.txt`).
- A random 256-bit AES key and a 128-bit IV are generated.
- The message is encrypted using AES-256 in CBC mode.
- The AES key is encrypted using User A’s RSA public key.
- Encrypted outputs:
  - `encrypted_message.bin` = IV + AES-encrypted message
  - `aes_key_encrypted.bin` = RSA-encrypted AES key

### 3. Message Decryption by User A
- User A uses their RSA private key to decrypt the AES key.
- The AES key is used to decrypt the message from `encrypted_message.bin`.
- The result is saved as `decrypted_message.txt`.

## Files
- `message.txt`: Original message
- `encrypted_message.bin`: Encrypted message
- `aes_key_encrypted.bin`: Encrypted AES key
- `decrypted_message.txt`: Final decrypted message (should match `message.txt`)
