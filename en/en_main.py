import hashlib
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import random
import string

BLOCK_SIZE = 16

def derive_key(key, length=32):
    return hashlib.sha256(key.encode('utf-8')).digest()

def pad_text(text):
    padder = padding.PKCS7(BLOCK_SIZE * 8).padder()
    padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
    return padded_data

def unpad_text(padded_text):
    unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
    text = unpadder.update(padded_text) + unpadder.finalize()
    return text.decode('utf-8')

def encrypt(text, key):
    padded_text = pad_text(text)
    iv = os.urandom(BLOCK_SIZE)
    derived_key = derive_key(key)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return urlsafe_b64encode(iv + encrypted).decode('utf-8')

def decrypt(encrypted_b64, key):
    encrypted_data = urlsafe_b64decode(encrypted_b64.encode('utf-8'))
    iv = encrypted_data[:BLOCK_SIZE]
    ciphertext = encrypted_data[BLOCK_SIZE:]
    derived_key = derive_key(key)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_text = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_text(padded_text)

def random_key():
    latin_chars = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation
    russian_upper = chr(1025) + ''.join(chr(i) for i in range(1040, 1072))
    russian_lower = chr(1105) + ''.join(chr(i) for i in range(1072, 1104))
    all_chars = latin_chars + digits + special_chars + russian_upper + russian_lower
    return ''.join(random.choices(all_chars, k=32))

def main():
    choice = input("Enter 1 for encryption, 2 for decryption, 3 for exit: ")
    
    if choice == '1':
        choice1 = input("Enter 1 for your key, 2 for random key: ")
        if choice1 == "1":
            text = input("Enter the text to encrypt: ")
            key = input("Enter the encryption key: ")
            encrypted = encrypt(text, key)
            print("Encrypted text:", encrypted)
        elif choice1 == "2":
            text = input("Enter the text to encrypt: ")
            key = random_key()
            encrypted = encrypt(text, key)
            print("Encrypted text:", encrypted)
            print("Key:", key)
    
    elif choice == '2':
        encrypted_b64 = input("Enter the encrypted text (in base64): ")
        key = input("Enter the encryption key: ")
        try:
            decrypted = decrypt(encrypted_b64, key)
            print("Decrypted text:", decrypted)
        except Exception as e:
            print("Decryption error. Check the data you entered.")

    elif  choice == '3':
        exit()
    
    else:
        print("Wrong choice. Enter 1 or 2.")

while True:
    if __name__ == "__main__":
        main()
