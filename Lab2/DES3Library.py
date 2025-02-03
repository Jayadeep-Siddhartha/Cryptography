from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

# Function to generate a valid 16-byte or 24-byte key for Triple DES
def get_3des_key(key):
    if len(key) == 16 or len(key) == 24:
        return key
    else:
        raise ValueError("Key must be either 16 or 24 bytes long for 3DES")

# Function to encrypt text using Triple DES
def des3_encrypt(plaintext, key):
    key = get_3des_key(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES3.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return binascii.hexlify(ciphertext).decode()

# Function to decrypt text using Triple DES
def des3_decrypt(ciphertext, key):
    key = get_3des_key(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(binascii.unhexlify(ciphertext))
    return unpad(decrypted_padded_text, DES3.block_size).decode()

# Function to encrypt a file
def encrypt_file(input_file, output_file, key):
    with open(input_file, 'r') as f:
        plaintext = f.read()
    ciphertext = des3_encrypt(plaintext, key)
    with open(output_file, 'w') as f:
        f.write(ciphertext)

# Function to decrypt a file
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'r') as f:
        ciphertext = f.read()
    decrypted_text = des3_decrypt(ciphertext, key)
    with open(output_file, 'w') as f:
        f.write(decrypted_text)

# User interaction
def main():
    key = b'16byteslongkey!!'  # Triple DES key must be 16 or 24 bytes long
    choice = input("Choose operation: 1. Encrypt Text  2. Decrypt Text  3. Encrypt File  4. Decrypt File: ")
    
    if choice == '1':
        plaintext = input("Enter text to encrypt: ")
        print("Ciphertext:", des3_encrypt(plaintext, key))
    elif choice == '2':
        ciphertext = input("Enter text to decrypt: ")
        print("Decrypted text:", des3_decrypt(ciphertext, key))
    elif choice == '3':
        input_file = input("Enter file path to encrypt: ")
        output_file = input("Enter output file path: ")
        encrypt_file(input_file, output_file, key)
        print("File encrypted successfully!")
    elif choice == '4':
        input_file = input("Enter file path to decrypt: ")
        output_file = input("Enter output file path: ")
        decrypt_file(input_file, output_file, key)
        print("File decrypted successfully!")
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()