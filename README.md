# Python Helper for Cryptography

This package is intented for simplifying the interfacing with the Python Cryptography package. The main goal is to make the user only have to think about the bytes rather than the asn1 structures that the Cryptography package uses.

This package can be used to establish a secure channel using Elliptic Curve Diffie-Hellman (defaults to curve secp256r1). The package allows for ephemeral usage by instantiating a new object each time you want a new shared secret. Messages are then encrypted with an AEAD procedure (defaults to ChaCha20-Poly1305).

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

(cipher, nonce) = ch.encrypt(b'Encrypted Hello world!')

# Send encrypted message and nonce to other party
# ...
```

## Usecases
It can be useful to only interact using raw byte representations of public keys. An example of such a scenario is if the other party is a microcontroller and it might be hard to use a ASN1 DER encoder/decoder.

## Notes
Some notes regarding the helper class.

### Nonce
The nonce can be set to an initial value when instantiating an object of the CryptoHelper class. The object will then internally increment the nonce for each encrypted message. Therefore, the nonce is unique for each encrypted message.
### Private members
All current class members are private to ensure that it is not possible to alter the keys and nonce (in order to prevent a nonce from being used more then once for a shared particular key). Also the AEAD class and the associated data (ad) are not modifiable since this could break the encryption/decryption process.

## TODO
- Incorporate the ability to check the authenticity of signed messages.
  - EdDSA
