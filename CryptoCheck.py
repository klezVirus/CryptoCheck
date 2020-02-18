import time
from libs import CryptoAlgorithm
import sys
import json
from libs.InputParser import InputParser


class CryptoChecker(object):
    def __init__(self):
        self.input_parser = InputParser()
        self.algorithm = None
        self.summary = {
            "ENCRYPT": {"FULL-PASS": 0, "PARTIAL-PASS": 0, "FAIL": 0},
            "DECRYPT": {"FULL-PASS": 0, "PARTIAL-PASS": 0, "FAIL": 0}
        }
        self.debug = {"encrypt": True, "decrypt": False}
        self.log_session = False

    def setup_algorithm(self, filename=None, algorithm=None, key=None) -> CryptoAlgorithm:
        algorithm = self.input_parser.guess(filename) if not algorithm else algorithm
        if algorithm == "hmac" or algorithm == "sha-256":
            self.algorithm = CryptoAlgorithm.HS256(key=key)
        elif algorithm == "aes-ecb":
            self.algorithm = CryptoAlgorithm.AES_ECB(key=key)
        elif algorithm == "aes-ctr":
            self.algorithm = CryptoAlgorithm.AES_CTR(key=key)
        elif algorithm == "aes-kw":
            self.algorithm = CryptoAlgorithm.AES_KW(key=key)
        else:
            print(f"[-] Algorithm `{algorithm}` not supported")
            sys.exit(1)

    def verify_encrypt(self, data):
        cipher = self.algorithm.encrypt(data["plain"])
        if cipher == data["cipher"]:
            self.summary["ENCRYPT"]["FULL-PASS"] += 1
        elif data["cipher"] in cipher:
            if self.debug["encrypt"]:
                print(f"{cipher} : {data['cipher']}")
            self.summary["ENCRYPT"]["PARTIAL-PASS"] += 1
        else:
            if self.debug["encrypt"]:
                print(f"{cipher} : {data['cipher']}")
            self.summary["ENCRYPT"]["FAIL"] += 1
        return cipher

    def verify_decrypt(self, data):
        plain = self.algorithm.decrypt(data["cipher"])
        if plain == data["plain"]:
            self.summary["DECRYPT"]["FULL-PASS"] += 1
        elif data["plain"] in plain:
            if self.debug["decrypt"]:
                print(f"{plain} : {data['cipher']}")
            self.summary["DECRYPT"]["PARTIAL-PASS"] += 1
        else:
            if self.debug["decrypt"]:
                print(f"{plain} : {data['cipher']}")
            self.summary["DECRYPT"]["FAIL"] += 1
        return plain

    def check(self, filename):
        data = self.input_parser.parse(filename=filename).get_data()
        for d in data:
            try:
                self.setup_algorithm(algorithm=d["type"], key=d["key"])
                d["test_ciphertext"] = self.verify_encrypt(d)
                d["test_plaintext"] = self.verify_decrypt(d)
            except TypeError as e:
                print(f"[-] Key: {d['key']}")
                print(f"[-] Plain: {d['plain']}")
                print(f"[-] Type Error: {e}")
                sys.exit(1)
            except Exception as e:
                print(f"[-] Key: {d['key']}")
                print(f"[-] Plain: {d['plain']}")
                print(f"[-] Unexpected Error: {e}")
                sys.exit(1)
        if self.log_session:
            self.save_data(data)
        print(f"[+] Summary: {json.dumps(self.summary)}")

    def save_data(self, data):
        label = time.strftime("%Y%m%d%H%M%S", time.localtime())
        with open(f"session_{label}.json", "w") as out:
            out.write(json.dumps(data))


if __name__ == "__main__":
    checker = CryptoChecker()
    if len(sys.argv) > 1:
        s = sys.argv[1]
        print(f"[+] Guessed filetype: {checker.input_parser.guess(s)}")
        checker.check(s)
