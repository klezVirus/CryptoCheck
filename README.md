# NIST-CAVS Extended Crypto Validator

This tool has been realised to validate the implementation of a set of encryption algorithms,
integrating and extending the tests provided by NIST-CAVS.

All the tests run by the tool are part of the [Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program), by NIST.

## Overview

The tool provide a way to extend the set of tests run by NIST-CAVS, generating new random
vectors or mutating existing FIPS vectors.
## CAVS vs ACVTS

[ACVTS](https://csrc.nist.gov/Projects/Automated-Cryptographic-Validation-Testing) will substitute CAVP as the standard system for encryption algorithm validation 
in July 2020. ACVTS uses an automatic tool for algorithm testing, called [ACVP](https://github.com/usnistgov/ACVP). 
With the advent of ACVP, this tool, still based on CAVS, may become obsolete.

However, due to its high usability, CryptoCheck may be still used while developing certain encryption 
algorithms, validating them before applying for compliance.

## Components

The tool is divided in three main components:

* CryptoGen: Generates random vectors to be used for encryption
* CryptoMutate: Mutate FIPS vectors using RBC (Random Byte Change) 
* CryptoCheck: Takes the output from IUT, then validate it against an independent implementation of the same algorithm

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

* CryptoCheck

```bash
$ python CryptoCheck.py examples/ecb.txt
[+] Guessed filetype: aes-ecb
{"ENCRYPT": {"FULL-PASS": 0, "PARTIAL-PASS": 5, "FAIL": 0}, "DECRYPT": {"FULL-PASS": 5, "PARTIAL-PASS": 0, "FAIL": 0}}

```

* CryptoMutate

```bash
$ python CryptoMutate.py -h
usage: CryptoMutate.py [-h] [-d] -v VECTORS [-k]

CryptoCheck - Random Vectors Generator

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Debug mode
  -v VECTORS, --vectors VECTORS
                        Save vectors to file
  -k, --keys            Mutate keys instead of plaintext
```

* CryptoGen

```bash
python CryptoGen.py
[+] Generating 256 vectors for: aes-ecb
COUNT = 0
KEY = 7d00cb22848a304a456de333e469c505aa07b8c0c88a49d012cee4c99706b52b
PLAINTEXT = 00000000000000000000000000000000

COUNT = 1
KEY = c57efc215caa03dd3aa873e46c1973e6cc14d9e765241a6ea5cbfbf241c399a2
PLAINTEXT = 00000000000000000000000000000000

COUNT = 2
KEY = 2b3bddbe5f9c83977c290fb01217cbc47a10e5fd4e64cb935a6d8f442416a084
PLAINTEXT = 00000000000000000000000000000000
```

## Limitations

* Currently, the tool doesn't implement MCT tests, but this feature will be added in future versions.
* Currently, the generation tool doesn't strictly follow FIPS vector file format. Even if unlikely, this can cause other tools (designed for these files), to fail while parsing them. This will be fixed in future versions.

## Algorithm Validation Systems Used

Currently, the algorithms tested are based on the following validation systems:

* The Advanced Encryption Standard Algorithm Validation Suite (AESAVS)
* Key Wrap Validation System (KWVS) 
* The Keyed-Hash Message Authentication Code Validation System (HMACVS) 
* The Secure Hash AlgorithmValidation System (SHAVS)