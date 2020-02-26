import binascii
import os
import random
import argparse
import re
import secrets
import sys

import in_place
from Crypto.Cipher import AES

from libs import CryptoAlgorithm


class CryptoMutate(object):
    def __init__(self, debug=False, vectors_dir=None, keys=False):
        self.debug = debug
        self.vectors_dir = vectors_dir
        self.keys = keys
        self.random = random.SystemRandom()
        self.crypto = None

    def __modify_byte(self, byte_string):
        byte_arr = list(byte_string)
        i = self.random.randint(0, len(byte_arr) - 1)
        byte_arr[i] = secrets.token_bytes(1) if not byte_arr[i] == b"\x00" else byte_arr[i]
        return bytes(byte_arr)

    def __modify_hex(self, hex_string):
        hex_arr = [(hex_string[i:i + 2]) for i in range(0, len(hex_string), 2)]
        i = self.random.randint(0, len(hex_arr) - 1)
        hex_arr[i] = secrets.token_hex(1) if not hex_arr[i] == "00" else hex_arr[i]
        return "".join(hex_arr)

    def __empty_hex(self, hex_string):
        hex_arr = [(hex_string[i:i + 2]) for i in range(0, len(hex_string), 2)]
        i = self.random.randint(0, len(hex_arr) - 1)
        hex_arr[i] = "00"
        return "".join(hex_arr)

    def setup_algorithm(self, tag, key):
        if self.keys:
            if tag == "K":
                self.crypto = CryptoAlgorithm.AES_KW(key)
            elif tag == "KEY":
                self.crypto = CryptoAlgorithm.AES_ECB(key=key)
        else:
            if tag == "K":
                return CryptoAlgorithm.AES_KW(key=key)
            elif tag == "KEY":
                self.crypto = CryptoAlgorithm.AES_ECB(key=key)
            else:
                print(f"[-] Something were wrong")
                sys.exit(1)

    def setup_and_encrypt(self, tag, key, msg):
        self.setup_algorithm(tag, key)
        return self.crypto.encrypt(msg)

    def setup_and_decrypt(self, tag, key, msg):
        self.setup_algorithm(tag, key)
        return self.crypto.decrypt(msg)

    def mutate(self):
        print(f"[+] Starting vectors' manipulation")
        for filename in os.listdir(self.vectors_dir):
            print(f"[+] Mutating {filename}")
            decrypt = False
            if filename.endswith(".req"):
                with in_place.InPlace(os.path.join(self.vectors_dir, filename)) as vectorsfile:
                    # Required for mutating the file upon decryption
                    pair = {"tag": None, "key": None}
                    for line in vectorsfile:
                        try:
                            if re.search(r"Decrypt", line):
                                decrypt = True
                            elif re.search(r"(Key|K|KEY)\s*=", line) and self.keys and not decrypt:
                                key = line.split("=")[1].strip()
                                new_key = self.__modify_hex(key)
                                if self.debug:
                                    print(f"[*] Mutating keys: {key} {new_key}")
                                line = line.replace(key, new_key)
                            elif re.search(r"(Msg|P|PLAINTEXT)\s*=", line) and not self.keys and not decrypt:
                                msg = line.split("=")[1].strip()
                                new_msg = self.__modify_hex(msg)
                                if self.debug:
                                    print(f"[*] Mutating plain: {msg} {new_msg}")
                                line = line.replace(msg, new_msg)
                            # Dead state, not reachable as not implemented yet
                            elif re.search(r"(K|KEY)\s*=", line) and self.keys and decrypt and False:
                                tag = line.split("=")[0].strip()
                                key = line.split("=")[1].strip()
                                new_key = self.__modify_hex(key)
                                pair["tag"] = tag
                                pair["key"] = new_key
                                if self.debug:
                                    print(f"[*] Mutating keys: {key} {new_key}")
                                line = line.replace(key, new_key)
                            elif re.search(r"(K|KEY)\s*=", line) and not self.keys and decrypt:
                                tag = line.split("=")[0].strip()
                                key = line.split("=")[1].strip()
                                pair["tag"] = tag
                                pair["key"] = key
                                if self.debug:
                                    print(f"[*] Not mutating keys: {key} {key}")
                            elif re.search(r"(C|CIPHERTEXT)\s*=", line) and decrypt and not self.keys:
                                msg = line.split("=")[1].strip()
                                if pair["key"] is None:
                                    if self.debug:
                                        print(f"[-] Error setting up the ciphertext at {filename} for {msg}")
                                else:
                                    plain = self.setup_and_decrypt(pair["tag"], pair["key"], msg)
                                    new_plain = self.__modify_hex(plain)
                                    new_msg = self.setup_and_encrypt(pair["tag"], pair["key"], new_plain)
                                    # Pair reset
                                    pair = {"tag": None, "key": None}
                                if self.debug:
                                    print(f"[*] Mutating cipher: {msg} {new_msg}")
                                line = line.replace(msg, new_msg)
                            vectorsfile.write(line)
                        except Exception as e:
                            print(f"[-] Error mutating {filename}")
                            print(f"[-] Exception: {e}")
            print(f"[+] Completed: {filename}")
        print(f"[+] Vectors' manipulation completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CryptoCheck - Random Vectors Generator', add_help=True)

    parser.add_argument(
        '-d', '--debug', required=False, action='store_true', default=False, help='Debug mode')
    parser.add_argument(
        '-v', '--vectors', required=True, type=str, default=None, help='Save vectors to file')
    parser.add_argument(
        "-k", "--keys", default=False, action="store_true", help="Mutate keys instead of plaintext")
    args = parser.parse_args()

    generator = CryptoMutate(debug=args.debug, vectors_dir=args.vectors, keys=args.keys)
    print(f"[+] Mutating vectors for {args.vectors}")
    generator.mutate()