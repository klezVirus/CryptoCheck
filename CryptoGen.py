import binascii
import random
import argparse
import secrets

from libs import CryptoAlgorithm


class CryptoGen(object):
    def __init__(self, debug=False, save_vectors=None, algorithm=None, count=None):
        self.debug = debug
        self.outfile = save_vectors
        self.algorithm = algorithm
        self.count = count
        self.max_length = 1024
        self.data = []
        self.random = random.SystemRandom()

    def render(self, data):
        if not type(data) == list:
            raise TypeError
        elif self.outfile == None:
            for line in data:
                for k, v in line.items():
                    print(f"{k} = {v}")
                print("")
        else:
            with open(self.outfile, "a") as out:
                for line in data:
                    for k, v in line:
                        out.write(f"{k} = {v}\n")
                    out.write("\n")

    def __random_hex(self, length):
        return secrets.token_hex(length)

    def __empty_hex(self, length):
        return f"{'00'*length}"

    def __generate_sha_vectors(self):
        for counter in range(self.count):
            length = self.random.randint(1, self.max_length)
            msg = self.__random_hex(length)
            vector = {"COUNT": counter, "Len": length, "Msg" : msg}
            self.data.append(vector)
        self.render(self.data)

    def __generate_hmac_vectors(self):
        for counter in range(self.count):
            length = 128  # self.random.randint(1, self.max_length)
            key_length = 40  # length//64
            key = self.__random_hex(key_length)
            msg = self.__random_hex(length)
            vector = {"COUNT": counter, "Klen": key_length, "Tlen": length//8, "Key": key, "Msg": msg}
            self.data.append(vector)
        self.render(self.data)

    def __generate_ecb_vectors(self):
        for counter in range(16):
            key = self.__random_hex(32)
            msg = self.__empty_hex(16)
            vector = {"COUNT": counter, "KEY": key, "PLAINTEXT": msg}
            self.data.append(vector)
        self.render(self.data)

    def __generate_kwae_vectors(self):
        for counter in range(self.count):
            key = self.__random_hex(32)
            msg = self.__random_hex(self.random.randint(1, self.max_length))
            vector = {"COUNT": counter, "K": key, "P": msg}
            self.data.append(vector)
        self.render(self.data)

    def __generate_kwad_vectors(self):
        for counter in range(self.count):
            key = self.__random_hex(32)
            crypto = CryptoAlgorithm.AES_KW(key=key)
            msg = self.__random_hex(self.random.randint(1, self.max_length))
            cipher = crypto.encrypt(msg)
            vector = {"COUNT": counter, "K": key, "C": cipher}
            self.data.append(vector)
        self.render(self.data)

    def generate(self):
        try:
            if self.algorithm == "sha":
                self.__generate_sha_vectors()
            elif self.algorithm == "hmac":
                self.__generate_hmac_vectors()
            elif self.algorithm == "aes-ecb":
                self.__generate_ecb_vectors()
            elif self.algorithm == "aes-kw-ad":
                self.__generate_kwad_vectors()
            elif self.algorithm == "aes-kw-ae":
                self.__generate_kwae_vectors()
        except Exception as e:
            print(f"[-] Error generating file for {self.algorithm}")
            print(f"[-] Exception: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='CryptoCheck - Random Vectors Generator', add_help=True)

    parser.add_argument(
        '-d', '--debug', required=False, action='store_true', default=False, help='Debug mode {0: None, 1: Encryption, 2: Decryption, 3: All}')
    parser.add_argument(
        '-s', '--save', required=False, type=str, default=None, help='Save vectors to file')
    parser.add_argument(
        '-n', '--count', required=False, type=int, default=256, help='How many vectors to create')
    parser.add_argument(
        '-a', '--algorithm', required=False, choices = ["aes-ecb", "aes-kwad", "aes-kwae", "sha", "hmac"], default="aes-ecb", help='Define the algorithm to use')
    args = parser.parse_args()

    generator = CryptoGen(debug=args.debug, save_vectors=args.save, algorithm=args.algorithm, count=args.count)
    print(f"[+] Generating {args.count} vectors for: {args.algorithm}")
    generator.generate()