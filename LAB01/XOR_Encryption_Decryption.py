import base64
from collections import Counter

# Step 1: Caesar decrypt function
def caesar_decrypt(ciphertext, shift):
    decrypted = ""
    for c in ciphertext:
        if c.isalpha():
            base = ord('a') if c.islower() else ord('A')
            decrypted += chr((ord(c) - base - shift) % 26 + base)
        else:
            decrypted += c
    return decrypted

# Check if two words are anagrams
def is_anagram(word1, word2):
    return Counter(word1) == Counter(word2)

# Step 1 & 2: Find the shift and passphrase
ciphertext = "mznxpz"
target_word = "secure"
found_shift = None
decrypted_text = None

for shift in range(1, 26):
    decrypted = caesar_decrypt(ciphertext, shift)
    if is_anagram(decrypted, target_word):
        found_shift = shift
        decrypted_text = decrypted
        break

if found_shift is None:
    print("Passphrase not found by anagram analysis.")
else:
    print(f"Step 1 & 2: Found shift = {found_shift}, decrypted text = {decrypted_text}")
    print(f"Passphrase (anagram of decrypted text): {target_word}")

# Step 3: XOR decrypt the base64 ciphertext with the passphrase

def xor_decrypt(cipher_bytes, key):
    key_bytes = key.encode()
    decrypted_bytes = bytearray()
    for i in range(len(cipher_bytes)):
        decrypted_bytes.append(cipher_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return decrypted_bytes

# Base64 ciphertext
base64_ciphertext = "Jw0KBlIMAEUXHRdFKyoxVRENEgkPEBwCFkQ="

# Decode base64 to bytes
cipher_bytes = base64.b64decode(base64_ciphertext)

# XOR decrypt using the passphrase
decrypted_bytes = xor_decrypt(cipher_bytes, target_word)

try:
    # Attempt to decode as UTF-8 text
    decrypted_message = decrypted_bytes.decode('utf-8')
except UnicodeDecodeError:
    decrypted_message = decrypted_bytes  # If not text, show raw bytes

print("\nStep 3: XOR Decryption result:")
print(decrypted_message)
