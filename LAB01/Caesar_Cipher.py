def caesar_decrypt(ciphertext, shift):
    decrypted = []
    for char in ciphertext:
        if char.isalpha():
            # Preserve case
            base = ord('A') if char.isupper() else ord('a')
            # Shift character and wrap around alphabet
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted.append(decrypted_char)
        else:
            decrypted.append(char)
    return ''.join(decrypted)

ciphertext = "Hvs Eiwqy Pfckb Tcl Xiadg Cjsf Hvs Zonm Rcu."

print("All possible shifts:\n")
for shift in range(26):
    decrypted_text = caesar_decrypt(ciphertext, shift)
    print(f"Shift {shift}: {decrypted_text}")

print("\nDecrypted text with shift 14:\n")
print(caesar_decrypt(ciphertext, 14))
