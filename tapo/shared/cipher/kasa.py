from base64 import b64decode, b64encode
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import serialization

from shared.cipher import TpLinkCipher


class KasaCipher(TpLinkCipher):
    def __init__(self, key: bytes = os.urandom(16), iv: bytes = os.urandom(16)):
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        self.pkcs7 = PKCS7(algorithms.AES.block_size)

    def encrypt(self, data: str) -> str:
        encryptor = self.cipher.encryptor()
        padder = self.pkcs7.padder()

        padded_data = padder.update(data.encode()) + padder.finalize()

        cipher_text = encryptor.update(padded_data) + encryptor.finalize()

        return b64encode(cipher_text).decode()

    def decrypt(self, data: str) -> bytes:
        decryptor = self.cipher.decryptor()
        unpadder = self.pkcs7.unpadder()

        padded_data = decryptor.update(b64decode(data.encode())) + decryptor.finalize()

        return unpadder.update(padded_data) + unpadder.finalize()

    def generate_handshake(self, public_key: str) -> str:
        public_key = serialization.load_pem_public_key(public_key.encode())

        encrypted = public_key.encrypt(self.key + self.iv, PKCS1v15())

        return b64encode(encrypted).decode()

    @staticmethod
    def decode_handshake(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        return private_key.decrypt(data, PKCS1v15())

    @staticmethod
    def get_public_key(public_key: rsa.RSAPublicKey) -> str:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    @staticmethod
    def generate_private_key() -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(65537, 1024)