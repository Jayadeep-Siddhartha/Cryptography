from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# Function to encrypt text using DES
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return binascii.hexlify(ciphertext).decode()

# Function to decrypt text using DES
def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_padded_text = cipher.decrypt(binascii.unhexlify(ciphertext))
    return unpad(decrypted_padded_text, DES.block_size).decode()

# Function to encrypt a file
def encrypt_file(input_file, output_file, key):
    with open(input_file, 'r') as f:
        plaintext = f.read()
    ciphertext = des_encrypt(plaintext, key)
    with open(output_file, 'w') as f:
        f.write(ciphertext)

# Function to decrypt a file
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'r') as f:
        ciphertext = f.read()
    decrypted_text = des_decrypt(ciphertext, key)
    with open(output_file, 'w') as f:
        f.write(decrypted_text)

# User interaction
def main():
    key = b'8bytekey'  # DES key must be 8 bytes long
    choice = input("Choose operation: 1. Encrypt Text  2. Decrypt Text  3. Encrypt File  4. Decrypt File: ")
    
    if choice == '1':
        plaintext = input("Enter text to encrypt: ")
        print("Ciphertext:", des_encrypt(plaintext, key))
    elif choice == '2':
        ciphertext = input("Enter text to decrypt: ")
        print("Decrypted text:", des_decrypt(ciphertext, key))
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
