import numpy as np

def mod_inverse(a, m):
    """Returns modular inverse of a under modulo m (if exists)"""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None  # No modular inverse exists

def text_to_numbers(text):
    """Converts text to numerical representation (A=0, B=1, ..., Z=25)"""
    return [ord(char) - ord('A') for char in text]

def numbers_to_text(numbers):
    """Converts numerical representation back to text"""
    return ''.join(chr(num + ord('A')) for num in numbers)

def hill_encrypt(plaintext, key_matrix):
    """Encrypts plaintext using Hill Cipher"""
    plaintext = plaintext.upper().replace(" ", "")
    
    # Ensure text length is a multiple of key size (add padding if needed)
    n = len(key_matrix)
    while len(plaintext) % n != 0:
        plaintext += 'X'  # Padding with 'X'

    # Convert plaintext to numbers
    text_vector = text_to_numbers(plaintext)
    
    # Encrypt in blocks of key size
    encrypted_text = []
    for i in range(0, len(text_vector), n):
        block = np.array(text_vector[i:i+n]).reshape(-1, 1)
        encrypted_block = np.dot(key_matrix, block) % 26
        encrypted_text.extend(encrypted_block.flatten())

    return numbers_to_text(encrypted_text)

def hill_decrypt(ciphertext, key_matrix):
    """Decrypts ciphertext using Hill Cipher"""
    n = len(key_matrix)
    ciphertext = ciphertext.upper().replace(" ", "")

    # Convert ciphertext to numbers
    text_vector = text_to_numbers(ciphertext)

    # Compute determinant and modular inverse
    det = int(round(np.linalg.det(key_matrix))) % 26
    det_inv = mod_inverse(det, 26)
    
    if det_inv is None:
        raise ValueError("Key matrix is not invertible modulo 26. Choose a different matrix.")

    # Compute modular inverse of key matrix
    adjugate = np.round(det * np.linalg.inv(key_matrix)).astype(int) % 26
    inverse_key_matrix = (det_inv * adjugate) % 26

    # Decrypt in blocks of key size
    decrypted_text = []
    for i in range(0, len(text_vector), n):
        block = np.array(text_vector[i:i+n]).reshape(-1, 1)
        decrypted_block = np.dot(inverse_key_matrix, block) % 26
        decrypted_text.extend(decrypted_block.flatten())

    return numbers_to_text(decrypted_text)

# ✅ Valid Key Matrix (2x2, must be invertible mod 26)
key_matrix = np.array([[3, 3], [2, 5]])
