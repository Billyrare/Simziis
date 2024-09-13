import rsa
def generate_keys(keysize=2048):
    (public_key, private_key) = rsa.newkeys(keysize)
    return public_key, private_key
def save_keys_to_file(public_key, private_key, public_key_file='public_key.pem', private_key_file='private_key.pem'):
    with open(public_key_file, 'wb') as pkey_file:
        pkey_file.write(public_key.save_pkcs1('PEM'))

    with open(private_key_file, 'wb') as prkey_file:
        prkey_file.write(private_key.save_pkcs1('PEM'))


def load_keys_from_file(public_key_file='public_key.pem', private_key_file='private_key.pem'):
    with open(public_key_file, 'rb') as pkey_file:
        public_key = rsa.PublicKey.load_pkcs1(pkey_file.read())

    with open(private_key_file, 'rb') as prkey_file:
        private_key = rsa.PrivateKey.load_pkcs1(prkey_file.read())

    return public_key, private_key


def encrypt_message(message, public_key):
    encrypted_message = rsa.encrypt(message.encode('utf8'), public_key)
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode('utf8')
    return decrypted_message


def sign_message(message, private_key):
    signature = rsa.sign(message.encode('utf8'), private_key, 'SHA-256')
    return signature


def verify_signature(message, signature, public_key):
    try:
        rsa.verify(message.encode('utf8'), signature, public_key)
        return True
    except:
        return False


# Генерация и сохранение ключей
public_key, private_key = generate_keys()
save_keys_to_file(public_key, private_key)

# Загрузка ключей
public_key, private_key = load_keys_from_file()

# Чтение сообщения, которое нужно зашифровать
message_to_encrypt = input("Введите сообщение для шифрования: ")

# Шифрование и расшифрование сообщения
encrypted_message = encrypt_message(message_to_encrypt, public_key)
print(f"Зашифрованное сообщение: {encrypted_message}")

decrypted_message = decrypt_message(encrypted_message, private_key)
print(f"Расшифрованное сообщение: {decrypted_message}")

# Создание и проверка цифровой подписи
signature = sign_message(message_to_encrypt, private_key)
is_valid_signature = verify_signature(message_to_encrypt, signature, public_key)
print(f"Подпись верна: {is_valid_signature}")
