from hashlib import sha1, sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


class KLAPv2Cipher:
    client_seed: bytes
    server_seed: bytes
    auth_hash: bytes

    lsk: bytes
    ldk: bytes
    ivb: bytes
    seq: int

    def __init__(self):
        self.client_seed = None
        self.server_seed = None
        self.auth_hash = None

        self.lsk = None
        self.ldk = None
        self.ivb = None
        self.seq = None

    def set_client_seed(self, client_seed: bytes):
        self.client_seed = client_seed
        self.setup_keys()

    def set_server_seed(self, server_seed: bytes):
        self.server_seed = server_seed
        self.setup_keys()

    def setup_keys(self):
        self.lsk = KLAPv2Cipher.get_lsk(self.client_seed, self.server_seed, self.auth_hash)
        self.ldk = KLAPv2Cipher.get_ldk(self.client_seed, self.server_seed, self.auth_hash)
        self.ivb = KLAPv2Cipher.get_ivb(self.client_seed, self.server_seed, self.auth_hash)
        self.seq = int.from_bytes(KLAPv2Cipher.get_seq(self.client_seed, self.server_seed, self.auth_hash), signed=True)

    def get_handshake1(self) -> bytes:
        server_auth_hash = KLAPv2Cipher._get_handshake1(self.client_seed, self.server_seed, self.auth_hash)
        return self.server_seed + server_auth_hash

    def get_handshake2(self) -> bytes:
        return KLAPv2Cipher._get_handshake2(self.client_seed, self.server_seed, self.auth_hash)

    def encrypt(self, data: str) -> bytes:
        return KLAPv2Cipher._encrypt(data.encode(), self.lsk, self.ivb, self.seq, self.ldk)

    def decrypt(self, data: bytes) -> str:
        return KLAPv2Cipher._decrypt(data, self.lsk, self.ivb, self.seq, self.ldk).decode()

    @staticmethod
    def get_auth_hash(username: str, password: str = None) -> bytes:
        username_hash = sha1(username.encode()).digest()
        password_hash = sha1(("kasaSetup" if username == "kasa@tp-link.net" else password).encode()).digest()

        return sha256(username_hash + password_hash).digest()

    @staticmethod
    def _get_handshake1(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        return sha256(local_seed + remote_seed + auth_hash).digest()
    
    @staticmethod
    def _get_handshake2(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        return sha256(remote_seed + local_seed + auth_hash).digest()
    
    @staticmethod
    def get_lsk(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        return sha256(b"lsk" + local_seed + remote_seed + auth_hash).digest()[0:16]
    
    @staticmethod
    def get_ldk(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        return sha256(b"ldk" + local_seed + remote_seed + auth_hash).digest()[0:28]

    @staticmethod
    def get_iv(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        return sha256(b"iv" + local_seed + remote_seed + auth_hash).digest()

    @staticmethod
    def get_ivb(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        return KLAPv2Cipher.get_iv(local_seed, remote_seed, auth_hash)[0:16]
    
    @staticmethod
    def get_seq(local_seed: bytes, remote_seed: bytes, auth_hash: bytes) -> bytes:
        print(KLAPv2Cipher.get_iv(local_seed, remote_seed, auth_hash).hex(), KLAPv2Cipher.get_iv(local_seed, remote_seed, auth_hash)[-4:], KLAPv2Cipher.get_iv(local_seed, remote_seed, auth_hash)[-4:].hex())
        return KLAPv2Cipher.get_iv(local_seed, remote_seed, auth_hash)[-4:]

    @staticmethod
    def _encrypt(data: bytes, lsk: bytes, ivb: bytes, seq: int, ldk: bytes):
        seq_bytes = seq.to_bytes(4, signed=True)

        iv = ivb[0:12] + seq_bytes

        cipher = Cipher(algorithms.AES(lsk), modes.CBC(iv))
        pkcs7 = PKCS7(algorithms.AES.block_size)

        encryptor = cipher.encryptor()
        padder = pkcs7.padder()

        padded_data = padder.update(data) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        hash = sha256(ldk + seq_bytes + encrypted).digest()

        return hash + encrypted

    @staticmethod
    def _decrypt(data: bytes, lsk: bytes, ivb: bytes, seq: int, ldk: bytes) -> bytes:
        seq_bytes = seq.to_bytes(4, signed=True)
        iv = ivb[0:12] + seq_bytes

        encrypted_hash = data[0:32]
        encrypted = data[32:]

        cipher = Cipher(algorithms.AES(lsk), modes.CBC(iv))
        pkcs7 = PKCS7(algorithms.AES.block_size)

        decryptor = cipher.decryptor()
        unpadder = pkcs7.unpadder()

        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        encrypted = unpadder.update(padded_data) + unpadder.finalize()

        hash = sha256(ldk + seq_bytes + encrypted)

        if encrypted_hash == hash:
            raise ValueError("invalid hash")
        
        return encrypted