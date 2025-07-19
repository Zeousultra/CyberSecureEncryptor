import base64
import os
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# ---------- AES ----------
def pad_aes(text): return text + (16 - len(text) % 16) * ' '

def aes_encrypt(text):
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = base64.b64encode(cipher.encrypt(pad_aes(text).encode())).decode()
    return encrypted, base64.b64encode(key).decode()

def aes_decrypt(ciphertext, encoded_key):
    try:
        key = base64.b64decode(encoded_key)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(base64.b64decode(ciphertext)).decode().strip()
    except:
        return "[!] AES Decryption failed."

# ---------- DES ----------
def pad_des(text): return text + (8 - len(text) % 8) * ' '

def des_encrypt(text):
    key = os.urandom(8)
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted = base64.b64encode(cipher.encrypt(pad_des(text).encode())).decode()
    return encrypted, base64.b64encode(key).decode()

def des_decrypt(ciphertext, encoded_key):
    try:
        key = base64.b64decode(encoded_key)
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.decrypt(base64.b64decode(ciphertext)).decode().strip()
    except:
        return "[!] DES Decryption failed."

# ---------- RSA ----------
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.publickey(), key

def rsa_encrypt(text, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    encrypted = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

def rsa_decrypt(ciphertext, priv_key):
    try:
        cipher = PKCS1_OAEP.new(priv_key)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode()
    except:
        return "[!] RSA Decryption failed."

# ---------- Main Menu ----------
def main():
    print("\n=== CyberSecureEncryptor ===")
    print("1. Encryption")
    print("2. Decryption")
    choice = input("Choose an option (1/2): ")

    if choice == '1':
        print("\n-- Encryption Menu --")
        print("1. AES")
        print("2. DES")
        print("3. RSA")
        enc_choice = input("Choose encryption algorithm (1/2/3): ")

        if enc_choice == '1':
            text = input("Enter text to encrypt (AES): ")
            ciphertext, key = aes_encrypt(text)
            print("\n[+] Encrypted Text:", ciphertext)
            print("[+] AES Key (save it!):", key)

        elif enc_choice == '2':
            text = input("Enter text to encrypt (DES): ")
            ciphertext, key = des_encrypt(text)
            print("\n[+] Encrypted Text:", ciphertext)
            print("[+] DES Key (save it!):", key)

        elif enc_choice == '3':
            text = input("Enter text to encrypt (RSA): ")
            pub_key, priv_key = generate_rsa_keys()
            ciphertext = rsa_encrypt(text, pub_key)
            print("\n[+] Encrypted Text:", ciphertext)
            print("[+] (Private key is used internally to decrypt immediately)")
            print("[+] Decrypted back:", rsa_decrypt(ciphertext, priv_key))

        else:
            print("[!] Invalid encryption option.")

    elif choice == '2':
        print("\n-- Decryption Menu --")
        print("1. AES")
        print("2. DES")
        print("3. RSA")
        dec_choice = input("Choose decryption algorithm (1/2/3): ")

        if dec_choice == '1':
            ciphertext = input("Enter AES encrypted text: ")
            key = input("Enter AES key: ")
            print("\n[+] Decrypted Text:", aes_decrypt(ciphertext, key))

        elif dec_choice == '2':
            ciphertext = input("Enter DES encrypted text: ")
            key = input("Enter DES key: ")
            print("\n[+] Decrypted Text:", des_decrypt(ciphertext, key))

        elif dec_choice == '3':
            print("[!] RSA Decryption skipped (requires stored private key, not supported here).")
        else:
            print("[!] Invalid decryption option.")

    else:
        print("[!] Invalid main option.")

if __name__ == "__main__":
    main()
