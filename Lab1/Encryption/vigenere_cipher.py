def vigenere_cipher(text, key, encrypt=True):
    key = key.upper()
    key_length = len(key)
    transformed_text = ""
    
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            shift = shift if encrypt else -shift
            base = ord('A') if char.isupper() else ord('a')
            transformed_text += chr((ord(char) - base + shift) % 26 + base)
        else:
            transformed_text += char

    return transformed_text

def vigenere_encrypt(text, key):
    return vigenere_cipher(text, key, encrypt=True)

def vigenere_decrypt(text, key):
    return vigenere_cipher(text, key, encrypt=False)
