# Python Helper for Cryptography

This package is intented for simplifying the interfacing with the Python Cryptography package. The main goal is to make the user only have to think about the bytes rather than the asn1 structures that the Cryptography package uses.

## Install
Currently not available to install from the pip repositories. Only installable by first cloning this repo and then running `python3 -m pip install -e [cloned repo directory]` (prefferably in a virtual environment).

I will probably upload the package to the pip repositories shortly.

## Usage
```python
from crypto_helper import CryptoHelper

ch = CryptoHelper()

# Receive other party's public key in bytes
# other_party_public_key = ...

# Retrieve my public key in raw byte format
my_public_key = ch.get_raw_public_key() # public key in bytes

# Send my_public_key to other party
# ...

# Create the shared secret key to establish a secure channel
ch.create_shared_secret(other_public_key)

(encrypted_msg, nonce) = ch.encrypt(b'"Encrypted Hello world!"')

# Send encrypted message and nonce to other party
```

## Usecases
It can be useful to only interact using raw byte representations of public keys. An example of such a scenario is if the other party is a microcontroller and it might be hard to use a ASN1 DER encoder/decoder.

## TODO
- Incorporate the ability to check the authenticity of signed messages.
  - EdDSA
