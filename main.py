import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from colorama import Fore, Style, init

# Initialisation de colorama
init(autoreset=True)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(padded_data) + unpadder.finalize()


def generate_password(length=16):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    return ''.join(secrets.choice(characters) for _ in range(length))


def main():
    password_file = "passwords.json"
    print(Fore.CYAN + "Bienvenue dans le Gestionnaire de mots de passe sécurisé.")
    master_password = input(Fore.YELLOW + "Créez votre mot de passe maître : ")
    salt = os.urandom(16)
    key = derive_key(master_password, salt)

    if os.path.exists(password_file):
        with open(password_file, "r") as file:
            passwords = json.load(file)
    else:
        passwords = {}

    while True:
        print(Fore.GREEN + "\n1. Générer un mot de passe")
        print(Fore.BLUE + "2. Récupérer un mot de passe")
        print(Fore.RED + "3. Quitter")
        choice = input(Fore.WHITE + "Choisissez une option : ")

        if choice == "1":
            service = input(Fore.YELLOW + "Nom du service (ex: Gmail, Facebook) : ")
            length = int(input(Fore.YELLOW + "Longueur du mot de passe : "))
            password = generate_password(length)
            encrypted_password = encrypt(password, key)
            passwords[service] = {
                "password": encrypted_password,
                "salt": base64.b64encode(salt).decode(),
            }
            with open(password_file, "w") as file:
                json.dump(passwords, file)
            print(Fore.GREEN + f"Mot de passe pour {service} généré et enregistré.")

        elif choice == "2":
            service = input(Fore.YELLOW + "Nom du service : ")
            if service in passwords:
                encrypted_password = passwords[service]["password"]
                salt = base64.b64decode(passwords[service]["salt"])
                key = derive_key(master_password, salt)
                password = decrypt(encrypted_password, key).decode()
                print(Fore.CYAN + f"Mot de passe pour {service} : {Fore.MAGENTA}{password}")
            else:
                print(Fore.RED + "Service introuvable.")

        elif choice == "3":
            print(Fore.RED + "Au revoir !")
            break

        else:
            print(Fore.RED + "Option invalide.")

if __name__ == "__main__":
    main()
