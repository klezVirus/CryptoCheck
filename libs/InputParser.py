import json
import os
import sys
import re
import sys


class InputParser(object):
    def __init__(self):
        self.keywords = {
            "aes-ecb": ["KEY", "PLAINTEXT", "CIPHERTEXT"],
            "sha-256": ["Msg", "MD"],
            "hmac": ["Key", "Msg", "Mac"],
            "aes-kw": ["K", "P", "C"]
        }
        self.current = {}
        self.data = []
        pass

    def checkfile(self, filename=None):
        if not os.path.isfile(filename):
            print(f"[-] The file '{filename}' was not found on this server")
            sys.exit(1)
        return filename

    def validate_filetype(self, filetype=None):
        if not filetype:
            print(f"[-] Unknown file format for `{filetype}`")
            sys.exit(1)
        return filetype

    def guess(self, filename=None):
        self.checkfile(filename)
        filetype = None
        with open(filename, "r") as infile:
            for line in infile:
                if re.search(r"PLAINTEXT|CIPHERTEXT", line):
                    filetype = "aes-ecb"
                elif re.search(r"([K|P|C]\s*=)", line):
                    filetype = "aes-kw"
                elif re.search(r"(MD\s*=)", line):
                    filetype = "sha-256"
                elif re.search(r"(Mac\s*=)", line):
                    filetype = "hmac"
                else:
                    continue
        return filetype

    def __init_current(self, filetype):
        self.current = {
            "type": filetype,
            "key": "",
            "plain": "",
            "cipher": ""
        }

    def __get_or_discard(self, message, filetype=None):
        if not filetype:
            return
        parts = message.split(" = ")
        if len(parts) != 2:
            return
        key, text = (parts[0].strip(), parts[1].strip())
        if key in self.keywords[filetype]:
            if key in ["K", "Key", "KEY"]:
                self.current["key"] = text
            elif key in ["P", "PLAINTEXT", "Msg"]:
                self.current["plain"] = text
            elif key in ["MD", "Mac", "C", "CIPHERTEXT"]:
                self.current["cipher"] = text
            if self.__parsed_one():
                self.data.append(self.current)
                self.current = {
                    "type": filetype,
                    "key": "",
                    "plain": "",
                    "cipher": ""
                }

    def __parsed_one(self):
        return all(self.current.values()) or (
                self.current["plain"] and self.current["cipher"] and self.current["type"] == "sha-256")

    def parse(self, filename=None):
        filetype = self.validate_filetype(self.guess(self.checkfile(filename)))
        self.__init_current(filetype)
        with open(filename, "r") as infile:
            for line in infile:
                self.__get_or_discard(line, filetype)
        return self

    def get_data(self):
        return self.data


if __name__ == "__main__":
    parser = InputParser()
    if len(sys.argv) > 1:
        s = sys.argv[1]
        print(f"[+] Guessed filetype: {parser.guess(s)}")
        parser.parse(s)
        print(f"[+] Data: {json.dumps(parser.get_data())}")
