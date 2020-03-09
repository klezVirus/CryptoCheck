import os
import time
from libs import CryptoAlgorithm
import sys
import json
from libs.InputParser import InputParser
import argparse


class CryptoChecker(object):
    def __init__(self, debug=0, extra_debug=False, save_session=False, label=""):
        self.input_parser = InputParser()
        self.algorithm = None
        self.label = label
        self.algorithm_name = ""
        self.summary = {
            "ENCRYPT": {"FULL-PASS": 0, "PARTIAL-PASS": 0, "FAIL": 0},
            "DECRYPT": {"FULL-PASS": 0, "PARTIAL-PASS": 0, "FAIL": 0}
        }
        self.extra_debug = extra_debug
        self.debug = {
            "encrypt":  bool(int(bin(debug)[2:].zfill(2)[1])),
            "decrypt":  bool(int(bin(debug)[2:].zfill(2)[0])),
        }
        self.log_session = save_session

    def setup_algorithm(self, filename=None, algorithm=None, key=None) -> CryptoAlgorithm:
        algorithm = self.input_parser.guess(filename) if not algorithm else algorithm
        self.algorithm_name = algorithm
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

    def verify_encrypt(self, data, strict_mode=False):
        try:
            cipher = self.algorithm.encrypt(data["plain"])
            if cipher == data["cipher"]:
                self.summary["ENCRYPT"]["FULL-PASS"] += 1
            elif data["cipher"] in cipher:
                if self.debug["encrypt"]:
                    print(f"{cipher} : {data['cipher']}")
                if strict_mode:
                    self.summary["ENCRYPT"]["PARTIAL-PASS"] += 1
                else:
                    self.summary["ENCRYPT"]["FULL-PASS"] += 1
            else:
                if self.debug["encrypt"]:
                    print(f"{cipher} : {data['cipher']}")
                self.summary["ENCRYPT"]["FAIL"] += 1
            return cipher
        except Exception as e:
            print(f"[-] Error: {e}")
            self.summary["ENCRYPT"]["FAIL"] += 1
            return "ERROR"

    def verify_decrypt(self, data, strict_mode=False):
        try:
            plain = self.algorithm.decrypt(data["cipher"])
            if plain == data["plain"]:
                self.summary["DECRYPT"]["FULL-PASS"] += 1
            elif data["plain"] in plain:
                if self.debug["decrypt"]:
                    print(f"{plain} : {data['cipher']}")
                if strict_mode:
                    self.summary["DECRYPT"]["PARTIAL-PASS"] += 1
                else:
                    self.summary["DECRYPT"]["FULL-PASS"] += 1
            else:
                if self.debug["decrypt"]:
                    print(f"{plain} : {data['cipher']}")
                self.summary["DECRYPT"]["FAIL"] += 1
            return plain
        except Exception as e:
            print(f"[-] Error: {e}")
            self.summary["DECRYPT"]["FAIL"] += 1
            return "ERROR"

    def update_state(self, data):
        if "verify-ciphertext" in data.keys():
            data["encryption-check"] = str(data["verify-ciphertext"] == data["cipher"]
                                           or
                                           data["cipher"] in data["verify-ciphertext"])
        if "verify-plaintext" in data.keys():
            data["decryption-check"] = str(data["verify-plaintext"] == data["plain"])

    def check(self, filename):
        data = self.input_parser.parse(filename=filename).get_data()
        for d in data:
            try:
                self.setup_algorithm(algorithm=d["type"], key=d["key"])
                d["verify-ciphertext"] = self.verify_encrypt(d)
                d["verify-plaintext"] = self.verify_decrypt(d)
                self.update_state(d)
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
            self.save_data(data, copyfilename=filename)
        print(f"[+] Summary: {json.dumps(self.summary)}")

    def save_data(self, data, copyfilename=None):
        try:
            os.makedirs('sessions')
        except Exception as e:
            if self.extra_debug:
                print(f"[-] Can't create session directory: {e}")
        if copyfilename:
            label = f"{self.label}{os.path.splitext(os.path.basename(copyfilename))[0]}_{time.strftime('%Y%m%d%H%M%S', time.localtime())}"
        else:
            label = f"{self.label}{self.algorithm_name}_{time.strftime('%Y%m%d%H%M%S', time.localtime())}"

        with open(f"sessions/session_{label}.json", "w") as out:
            out.write(json.dumps(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CryptoCheck - A simple encryption algorithm validator based on NIST CAVS', add_help=True)

    parser.add_argument(
        '-d', '--debug', required=False, type=int, default=0, help='Debug mode {0: None, 1: Encryption, 2: Decryption, 3: All}')
    parser.add_argument(
        '-s', '--save', required=False, action='store_true', default=False, help='Save check session to file')
    parser.add_argument(
        '-dd', '--extradebug', required=False, action='store_true', default=False, help='Enable extra debug messages')
    parser.add_argument(
        '-l', '--label', required=False, type=str, default="", help='Label to add to the session file')
    parser.add_argument(
        'file', type=str, help='File to parse')

    args = parser.parse_args()

    checker = CryptoChecker(debug=args.debug, extra_debug=args.extradebug, save_session=args.save, label=args.label)
    s = args.file
    print(f"[+] Guessed filetype: {checker.input_parser.guess(s)}")
    checker.check(s)
