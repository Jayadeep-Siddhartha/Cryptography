from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key():
    """Generate a random 256-bit (32-byte) AES key."""
    return get_random_bytes(32)

def encrypt(plaintext, key):
    """Encrypt plaintext using AES CBC mode."""
    iv = get_random_bytes(16)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

def decrypt(ciphertext_b64, key):
    """Decrypt ciphertext using AES CBC mode."""
    ciphertext = base64.b64decode(ciphertext_b64)
    iv, encrypted_data = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()

# Example usage
if __name__ == "__main__":
    key = generate_key()  # Store this securely
    plaintext = "Hello, AES Encryption!"
    
    encrypted_text = encrypt(plaintext, key)
    print("Encrypted:", encrypted_text)
    
    decrypted_text = decrypt(encrypted_text, key)
    print("Decrypted:", decrypted_text)
