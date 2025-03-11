from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto import Random

def rc4_encrypt(key, plaintext):
    nonce = Random.new().read(16)  
    tempkey = SHA.new(key + nonce).digest() 
    cipher = ARC4.new(tempkey)
    ciphertext = cipher.encrypt(plaintext.encode())
    return nonce + ciphertext

def rc4_decrypt(key, encrypted_data):
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:] 
    tempkey = SHA.new(key + nonce).digest()
    decipher = ARC4.new(tempkey)
    return decipher.decrypt(ciphertext).decode()

key = b"Secret"
message = "DemoText"

encrypted_msg = rc4_encrypt(key, message)
print(f"Encrypted: {encrypted_msg}") 

decrypted_msg = rc4_decrypt(key, encrypted_msg)
print(f"Decrypted: {decrypted_msg}")
