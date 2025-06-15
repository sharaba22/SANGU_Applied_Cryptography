def caesar_decrypt(ciphertext, shift):
    """
    Decrypts the ciphertext using a Caesar cipher with the given shift.

    Parameters:
    - ciphertext (str): The encrypted text.
    - shift (int): The number of letters to shift backward to decrypt.

    Returns:
    - str: The decrypted plaintext.
    """
    decrypted = ""  # Store the decrypted output here

    for char in ciphertext:
        # Check if the character is a letter (A-Z or a-z)
        if char.isalpha():
            # Determine ASCII base depending on uppercase or lowercase
            base = ord('A') if char.isupper() else ord('a')
            # Shift character backward by 'shift' within alphabet range (0-25)
            decrypted += chr((ord(char) - base - shift) % 26 + base)
        else:
            # Non-alphabetic characters remain unchanged (spaces, punctuation)
            decrypted += char

    return decrypted


ciphertext = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."

print("Brute-force Caesar Cipher Decryption:\n")

# Try all possible shifts from 1 to 25 (26 would be original text)
for shift in range(1, 26):
    # Print shift number and decrypted text with that shift
    print(f"Shift {shift:2}: {caesar_decrypt(ciphertext, shift)}")
