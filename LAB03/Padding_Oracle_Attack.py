from binascii import unhexlify, hexlify
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16 # AES block size (16 bytes)
KEY = b"this_is_16_bytes"

# Ciphertext = IV + encrypted blocks (from check_decrypt.py success)
CIPHERTEXT_HEX = (
    "746869735f69735f31365f6279746573"
    "9404628dcdf3f003482b3b0648bd920b"
    "3f60e13e89fa6950d3340adbbbb41c12"
    "b3d1d97ef97860e9df7ec0d31d13839a"
    "e17b3be8f69921a07627021af16430e1"
)

def padding_oracle(ciphertext: bytes) -> bool:
    """Returns True if the ciphertext decrypts with valid padding, False otherwise."""
    if len(ciphertext) % BLOCK_SIZE != 0:
        return False

    try:
        iv = ciphertext[:BLOCK_SIZE]
        ct = ciphertext[BLOCK_SIZE:]
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ct) + decryptor.finalize()

        unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
        unpadder.update(decrypted)
        unpadder.finalize()
        return True
    except (ValueError, TypeError):
        return False

# Task 2: Split ciphertext into 16-byte blocks
def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """Split data into blocks of the specified size."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# Task 3: Decrypt one block using padding oracle
def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Decrypt a single block using the padding oracle attack. Returns the decrypted plaintext block."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    # Start from last byte to the first
    for i in range(1, BLOCK_SIZE + 1):
        padding_value = i.to_bytes(1, 'big')

        for guess in range(256):
            # Make a copy to modify
            modified_block = bytearray(prev_block)

            # Change the last i-1 bytes to match padding
            for j in range(1, i):
                modified_block[-j] ^= intermediate[-j] ^ i

            # Change the target byte to our guess
            modified_block[-i] ^= guess ^ i

            # Combine the modified block and real target block
            crafted = bytes(modified_block) + target_block

            # Check if the padding is valid
            if padding_oracle(crafted):
                intermediate[-i] = guess ^ i
                plaintext[-i] = intermediate[-i] ^ prev_block[-i]
                break

    return bytes(plaintext)

# Task 4: Decrypt full ciphertext
def padding_oracle_attack(ciphertext: bytes) -> bytes:
    """Perform the padding oracle attack on the entire ciphertext."""
    blocks = split_blocks(ciphertext)
    plaintext = b""

    # Start from block 1 (block 0 is IV)
    for i in range(1, len(blocks)):
        plain = decrypt_block(blocks[i - 1], blocks[i])
        plaintext += plain

    return plaintext

# Task 5: Remove padding and decode bytes to text
def unpad_and_decode(plaintext: bytes) -> str:
    """Attempt to unpad and decode the plaintext."""
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    data = unpadder.update(plaintext) + unpadder.finalize()
    return data.decode("utf-8", errors="ignore")

# Main program that runs the attack
if __name__ == "__main__":
    try:
        # Convert hex string to bytes
        ciphertext = unhexlify(CIPHERTEXT_HEX)
        print(f"[*] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[*] IV: {ciphertext[:BLOCK_SIZE].hex()}")

        # Start the attack
        recovered = padding_oracle_attack(ciphertext)

        print("\n[+] Decryption complete!")
        print(f" Recovered plaintext (raw bytes): {recovered}")
        print(f" Hex: {recovered.hex()}")

        # Try to convert to readable text
        decoded = unpad_and_decode(recovered)
        print("\n Final plaintext:")
        print(decoded)

    except Exception as e:
        print(f"\n Error occurred: {e}")