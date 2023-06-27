import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def asymmetric_decrypt(cipher, key):
    return key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def asymmetric_encrypt(plain_json, key):
    plain = json.dumps(plain_json)
    plain = plain.encode('utf-8')
    cipher = key.encrypt(
        plain,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain, cipher


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
    return public_key.verify(
        signature,
        plain,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def set_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
    return serialization.load_pem_public_key(key_str.read())


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
