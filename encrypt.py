from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import base64
import os

# Получение пароля от пользователя
password_provided = getpass("Введите пароль: ") 
password = password_provided.encode() 

# Создание ключа на основе пароля и случайной соли
salt = os.urandom(16)

# Сохранение соли в файл
with open("salt.txt", "wb") as salt_file:
    salt_file.write(salt)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))

def encrypt(private_key, key):
    """
    Шифрование приватного ключа
    """
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(private_key)
    return encrypted_text

# Чтение файла, шифрование и запись обратно в файл
with open('private_keys.txt', 'r+') as file:
    lines = file.readlines()
    file.seek(0)
    for line in lines:
        encrypted_line = encrypt(line.strip().encode(), key)
        file.write(encrypted_line.decode() + '\n')
    file.truncate()
