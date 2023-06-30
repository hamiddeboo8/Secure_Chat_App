import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hashlib

def get_dh_key():
    private_key = ec.generate_private_key(ec.SECP384R1())
    return private_key

def get_dh_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)



def asymmetric_decrypt(cipher_text, key):
    return key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def asymmetric_encrypt(plain_text, key):
    return key.encrypt(
        plain_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def symmetric_decrypt(cipher_text, cipher):
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text)


def symmetric_encrypt(plain_text, cipher):
    encryptor = cipher.encryptor()
    return encryptor.update(plain_text)


def sign(message, private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(plain, signature, public_key):
    try:
        public_key.verify(
            signature,
            plain,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except:
        return False


def set_key():
    key = os.urandom(32)
    iv = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, iv)
    cipher = Cipher(algorithm, mode=None)
    return key, iv, cipher


def get_cipher(key, iv):
    algorithm = algorithms.ChaCha20(key, iv)
    return Cipher(algorithm, mode=None)


def encrypt_user_messages(plain_text, password):
    h_password = hashlib.sha256(password).hexdigest()
    cipher = get_cipher(h_password[:32].encode('latin-1'), h_password[32:48].encode('latin-1'))
    return symmetric_encrypt(plain_text.encode('latin-1'), cipher)


def decrypt_user_messages(cipher_text, password):
    h_password = hashlib.sha256(password).hexdigest()
    cipher = get_cipher(h_password[:32].encode('latin-1'), h_password[32:48].encode('latin-1'))
    return symmetric_decrypt(cipher_text, cipher).decode('latin-1')


def set_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    return private_key, public_key


def save_key(key, key_name, password):
    pass_bytes = bytes(password, 'utf-8')
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pass_bytes)
    )
    with open(f'./keys/{key_name}/key.pem', 'wb') as key_file:
        key_file.write(pem)


def deserialize_public_key(key_str):
    return serialization.load_pem_public_key(key_str)


def serialize_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def save_server_keys(private_key, public_key):
    pass_bytes = bytes('1234', 'utf-8')
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pass_bytes)
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(f'./private-server-key.pem', 'wb') as key_file:
        key_file.write(private_pem)
    with open(f'./public-server-key.pem', 'wb') as key_file:
        key_file.write(public_pem)


def load_server_keys():
    with open('./private-server-key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=bytes('1234', 'utf-8'),
        )
    return private_key, private_key.public_key()


def load_server_public_key():
    with open('./public-server-key.pem', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key


def get_keys(key_path, password):
    with open(key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=bytes(password, 'utf-8'),
        )
    return private_key, private_key.public_key()
