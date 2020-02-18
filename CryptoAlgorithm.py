import json
import sys
from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
from pskc.crypto.aeskw import wrap, unwrap


class CryptoAlgorithm(ABC):
    @abstractmethod
    def __init__(self, key):
        self.key = binascii.unhexlify(key.encode())

    @abstractmethod
    def encrypt(self, message) -> str:
        pass

    @abstractmethod
    def decrypt(self, message) -> str:
        pass

    def encrypt_with(self, message, key=None) -> str:
        self.update_key(key)
        self.encrypt(message)

    def decrypt_with(self, message, key=None) -> str:
        self.update_key(key)
        self.decrypt(message)

    def update_key(self, key=None):
        if key:
            self.key = key.encode()

    def compare(self, plaintext, ciphertext):
        return self.encrypt(plaintext) == ciphertext

    @staticmethod
    def verify(self, cipher, tag):
        try:
            cipher.verify(tag)
            return True
        except ValueError as e:
            print(f"[-] {e}")
            return False


class AES_EAX(CryptoAlgorithm):

    def __init__(self, key):
        CryptoAlgorithm.__init__(self, key)
        self.nonce = None
        self.header = None

    def encrypt(self, message, header=None):
        cipher = AES.new(self.key, AES.MODE_EAX)
        self.nonce = cipher.nonce
        self.header = header
        ciphertext, tag = cipher.encrypt_and_digest(message)
        return self.verify(cipher, tag)

    def decrypt(self, message, header=None, nonce=None, tag=None):
        try:
            nonce = nonce if nonce else self.nonce
            header = header if header else self.header
            cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
            cipher.update(header)
            if tag:
                plaintext = cipher.decrypt_and_verify(message, tag)
            else:
                plaintext = cipher.decrypt(message)
            return plaintext
        except ValueError as e:
            print(f"[-] {e}")
            return None


class AES_ECB(CryptoAlgorithm):

    def __init__(self, key):
        CryptoAlgorithm.__init__(self, key)

    def encrypt(self, message):
        cipher = AES.new(self.key, AES.MODE_ECB)
        message = binascii.unhexlify(message)
        try:
            ciphertext = cipher.encrypt(pad(message, AES.block_size))
        except Exception as e:
            print(f"[-] Error: {e}")
            try:
                ciphertext = cipher.encrypt(message)
            except Exception as e:
                print(f"[-] Error: {e}")
                sys.exit(1)
        return binascii.hexlify(ciphertext).decode()

    def decrypt(self, message):
        message = binascii.unhexlify(message)
        cipher = AES.new(self.key, AES.MODE_ECB)
        try:
            plaintext = unpad(cipher.decrypt(message), AES.block_size)
        except Exception as e:
            print(f"[-] Error: {e}")
            try:
                plaintext = cipher.decrypt(message)
            except Exception as e:
                print(f"[-] Error: {e}")
                sys.exit(1)
        return binascii.hexlify(plaintext).decode()


class AES_CBC(CryptoAlgorithm):

    def __init__(self, key):
        CryptoAlgorithm.__init__(self, key)
        self.iv = None

    def encrypt(self, message):
        cipher = AES.new(self.key, AES.MODE_CBC)
        cipherbytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        self.iv = b64encode(cipher.iv).decode('utf-8')
        ciphertext = b64encode(cipherbytes).decode('utf-8')
        return ciphertext

    def decrypt(self, message, iv=None):
        # Assumes both iv and message are b64 encoded
        iv = iv if iv else self.iv
        try:
            iv = b64decode(iv)
            message = b64decode(message)
        except ValueError as e:
            print(f"[-] {e}")
            pass
        cipher = AES.new(self.key, AES.MODE_CTR, iv)
        plaintext = unpad(cipher.decrypt(message), AES.block_size)
        return plaintext


class AES_CTR(CryptoAlgorithm):

    def __init__(self, key):
        CryptoAlgorithm.__init__(self, key)
        self.nonce = None

    def encrypt(self, message):
        cipher = AES.new(self.key, AES.MODE_CTR)
        message = binascii.unhexlify(message)
        cipherbytes = cipher.encrypt(message)
        self.nonce = binascii.hexlify(cipher.nonce).decode('utf-8')
        ciphertext = binascii.hexlify(cipherbytes).decode('utf-8')
        return ciphertext

    def decrypt(self, message, nonce=None):
        # Assumes both iv and message are hex encoded
        nonce = nonce if nonce else self.nonce
        try:
            nonce = binascii.hexlify(nonce)
            message = binascii.unhexlify(message)
        except ValueError as e:
            print(f"[-] {e}")
            pass
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(message)
        return plaintext


class AES_KW(CryptoAlgorithm):

    def __init__(self, key):
        CryptoAlgorithm.__init__(self, key)
        self.seed = None

    def update_seed(self, seed):
        try:
            self.seed = int(seed, 16)
        except ValueError as e:
            print(f"[-] {e}")
            pass

    def encrypt(self, message):
        try:
            return self.__wrap(message)
        except ValueError as e:
            print(f"[-] Wrong Key Length")

    def decrypt(self, message):
        return self.__unwrap(message)

    def __wrap(self, message):
        kek = self.key
        plain = binascii.unhexlify(message)
        if self.seed:
            return binascii.hexlify(wrap(key=kek, plaintext=plain, iv=self.seed)).decode()
        else:
            return binascii.hexlify(wrap(key=kek, plaintext=plain)).decode()

    def __unwrap(self, message):
        kek = self.key
        cipher = binascii.unhexlify(message)
        if self.seed:
            return binascii.hexlify(unwrap(key=kek, ciphertext=cipher, iv=self.seed)).decode()
        else:
            return binascii.hexlify(unwrap(key=kek, ciphertext=cipher)).decode()


class HS256(CryptoAlgorithm):
    def __init__(self, key):
        CryptoAlgorithm.__init__(self, key)
        self.digest_mode = SHA256

    def encrypt(self, message) -> str:
        message = binascii.unhexlify(message)
        return self.__hex_digest(message, key=self.key)

    def decrypt(self, message) -> str:
        message = binascii.unhexlify(message)
        return self.__hex_digest(message, key=self.key)

    def to_bytes(self, string):
        if type(string) == "str":
            return string.encode()
        else:
            return string

    def __hex_digest(self, data=None, key=None):
        h = HMAC.new(self.to_bytes(key), digestmod=SHA256) if key else SHA256.new()
        h.update(self.to_bytes(data))
        return h.hexdigest()

    def verify(self, hex_digest=None, data=None, key=None):
        if key:
            return HMAC.new(self.to_bytes(key), digestmod=SHA256).hexverify(hex_digest)
        else:
            return self.__hex_digest(data) == hex_digest
