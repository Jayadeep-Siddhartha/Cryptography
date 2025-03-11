# from math import gcd

# def encrypt(message, e, n):
#     cipher = (message ** e) % n
#     print('CipherText : ', cipher)

# def decrypt(message, d, n):
#     plainText = (message ** d) % n
#     print('PlainText : ', plainText)


# def RSA(message, operation):
#     p = 101
#     q = 103

#     n = p * q
#     phi = (p - 1) * (q - 1)

#     for i in range(2, phi):
#         if gcd(i, phi) == 1:
#             e = i
#             break

#     d = 0
#     while True:
#         if d * e % phi == 1:
#             break
#         d += 1

#     if operation == 1:
#         encrypt(message, e, n)
#     else:
#         decrypt(message, d, n)

# message = int(input('Enter message(number) : '))
# operation = input('Press 1 for Encryption \nPress 2 for Decryption\nEnter your operation : ')

# RSA(message, operation)


import random
from sympy import isprime

def generate_prime(bits=8):
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return None

def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 2
    while gcd(e, phi) != 1:
        e += 1
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def encrypt(plain_text, key):
    e, n = key
    return [pow(ord(char), e) % n for char in plain_text]

def decrypt(cipher_text, key):
    d, n = key
    return ''.join(chr(pow(char, d) % n) for char in cipher_text)

# Generate keys
public_key, private_key = generate_keys()
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")

# Encrypt a number (converted to string first)
number = "7"
encrypted_number = encrypt(number, public_key)
decrypted_number = decrypt(encrypted_number, private_key)
print(f"Encrypted Number: {encrypted_number}")
print(f"Decrypted Number: {decrypted_number}")

# Encrypt an alphabet
alphabet = "A"
encrypted_alphabet = encrypt(alphabet, public_key)
decrypted_alphabet = decrypt(encrypted_alphabet, private_key)
print(f"Encrypted Alphabet: {encrypted_alphabet}")
print(f"Decrypted Alphabet: {decrypted_alphabet}")

