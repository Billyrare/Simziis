from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Генерация секретного и открытого ключей
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_key_pem)

    with open('public_key.pem', 'wb') as f:
        f.write(public_key_pem)

# Шифрование
def encrypt_message(public_key_file, input_file, output_file):
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    with open(input_file, 'r', encoding='utf-8') as f:
        plaintext = f.read()

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

# Расшифрование
def decrypt_message(private_key_file, input_file, output_file):
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(plaintext)
def test_encryption_decryption(test_files):
    for i, file in enumerate(test_files):
        try:
            print(f"Тест {i + 1}:")
            print(f"Шифрование файла {file}...")
            encrypt_message('public_key.pem', file, f'encrypted_{i}.txt')

            print(f"Расшифровка файла encrypted_{i}.txt...")
            decrypt_message('private_key.pem', f'encrypted_{i}.txt', f'decrypted_{i}.txt')

            # Сравнение исходного файла с расшифрованным
            with open(file, 'r', encoding='utf-8') as original, open(f'decrypted_{i}.txt', 'r', encoding='utf-8') as decrypted:
                if original.read() == decrypted.read():
                    print("Тест пройден: Расшифрованные данные соответствуют исходным.\n")
                else:
                    print("Тест не пройден: Расшифрованные данные не соответствуют исходным.\n")
        except Exception as e:
            print(f"Ошибка в тесте {i + 1}: {e}")

if __name__ == '__main__':
    generate_keys()

    # Указать пути к вашим 10 тестовым файлам
    test_files = ['text1.txt', 'text2.txt', 'text3.txt', 'text4.txt', 'text5.txt', 'text6.txt', 'text7.txt', 'text8.txt', 'text9.txt', 'text10.txt']
    test_encryption_decryption(test_files)
    encrypt_message('public_key.pem', 'to_decrypt.txt', 'encrypted.txt')
    decrypt_message('private_key.pem', 'encrypted.txt', 'decrypted.txt')

