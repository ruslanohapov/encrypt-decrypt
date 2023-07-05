from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass
import base64
import os

# Получение пароля от пользователя
password_provided = getpass("Введите пароль: ") 
password = password_provided.encode() 

# Загрузка сохраненной соли
with open("salt.txt", "rb") as salt_file:
    salt = salt_file.read()

# Восстановление ключа из пароля и соли
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))

def decrypt(encrypted_private_key, key):
    """
    Расшифровка приватного ключа
    """
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_private_key)
    return decrypted_text

# Чтение зашифрованных ключей из файла, расшифровка и запись обратно в файл
with open('private_keys.txt', 'r+') as file:
    lines = file.readlines()
    file.seek(0)
    for line in lines:
        decrypted_line = decrypt(line.strip().encode(), key)
        file.write(decrypted_line.decode() + '\n')
    file.truncate()
