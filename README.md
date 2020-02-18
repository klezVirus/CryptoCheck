# CryptoCheck

This tool has been realised to validate a specific hardware based implementation of some common encryption/crypto-hashing algorithms.

## Overview

The tool takes as input the output of iStorage AutoTestingKit Tool, normalise its data, and use an independent implementation of each algorithm to validate they are implemented properly at hardware level.


## How it works

The tool operates in three steps:

1. Parse the output file
2. Normalise the data
    * Key
    * Plaintext
    * Ciphertext
3. Indpendently encrypt/decrypt the data, checking if:
    * encrypt(key, plaintext) == ciphertext
    * decrypt(key, ciphertext) == plaintext


## Usage

```
$ python CryptoCheck.py examples/ecb.txt
[+] Guessed filetype: aes-ecb
{"ENCRYPT": {"FULL-PASS": 0, "PARTIAL-PASS": 5, "FAIL": 0}, "DECRYPT": {"FULL-PASS": 5, "PARTIAL-PASS": 0, "FAIL": 0}}

```
