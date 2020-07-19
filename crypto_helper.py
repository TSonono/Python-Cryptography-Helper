from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules import rfc5280
from pyasn1.type import univ
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import aead

RFC_5280_UNCROMPRESSED_BYTE = b'\x04'


class CryptoHelper(object):

    def __init__(self, ad=None, initial_nonce=bytes(12),
                 ecdh_curve=ec.SECP256R1(), aead_class=aead.ChaCha20Poly1305,
                 nonce_increment=2):
        """Helper class for cryptographic operations using bytes to interface

        Args:
            ad (str, optional): The associated data to use during
                encryption/decryption. Defaults to None.
            initial_nonce (bytes, optional): The initial nonce value to use
                during encryption/decryption. Defaults to bytes(12).
            ecdh_curve (EllipticCurve, optional): Which elliptic curve to use
                in ECDH. Defaults to ec.SECP256R1().
            aead_class (ChaCha20Poly1305 || AESCCM || AESGCM, optional): The
                AEAD to use during encryption/decryption.
                Defaults to ChaCha20Poly1305.
            nonce_increment (int): The value that the nonce should be
                incremented with for each encrypted message

        Raises:
            ValueError: If the nonce_increment argument is 0
        """
        if (nonce_increment == 0):
            raise ValueError("Nonce increment must not be 0")
        self._nonce_increment = nonce_increment

        self._private_key = ec.generate_private_key(
            ecdh_curve, default_backend())

        self._shared_secret = None
        self._public_key = self._private_key.public_key()
        self._nonce = initial_nonce
        self._ad = ad
        self._aead_class = aead_class
        self._nonce_len = len(initial_nonce)

    def get_raw_public_key(self):
        """Returns the public key in raw bytes

        Returns:
            bytes: The raw public key in bytes
        """
        public_key_der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self._public_key_decoded, _ = der_decoder(
            public_key_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
        public_key_bits = self._public_key_decoded[1]
        # Remove the first byte, it only indicates if key is compressed
        return bytes(public_key_bits.asNumbers())[1:]

    def create_shared_secred(self, other_public_key):
        """Creates the shared key used to encrypt messages

        Args:
            other_public_key (bytes): Other party's public key
        """
        algorithm = self._public_key_decoded["algorithm"]

        other_public_key_asn1 = rfc5280.SubjectPublicKeyInfo()
        other_public_key_asn1["algorithm"] = algorithm
        other_public_key_asn1['subjectPublicKey'] = (
            univ.BitString.fromOctetString(
                RFC_5280_UNCROMPRESSED_BYTE + other_public_key))

        other_public_key_der = serialization.load_der_public_key(
            der_encoder(other_public_key_asn1,
                        asn1Spec=rfc5280.SubjectPublicKeyInfo()),
            backend=default_backend())
        self._shared_secret = self._private_key.exchange(
            ec.ECDH(), other_public_key_der)

    def encrypt(self, msg):
        """Encrypt a message using the shared secret

        Args:
            msg (bytes): Plain text to be encrypted

        Returns:
            tuple: (bytes: cipher, bytes: nonce)

        Raises:
            PermissionError: If there is no shared key created prior to
                attempting to encrypt
        """
        if (self._shared_secret is None):
            raise PermissionError("No shared key generated yet")

        cipher_object = self._aead_class(self._shared_secret)
        cipher = cipher_object.encrypt(self._nonce, msg, self._ad)
        result = (bytes(cipher), self._nonce)
        self.__increment_nonce()
        return result

    def decrypt(self, cipher, nonce):
        """Decrypt a cipher using the shared secret

        Args:
            cipher (bytes): Cipher to be decrypted
            nonce (bytes): Nonce to be used when decrypting

        Returns:
            bytes: The decrypted message in plain text

        Raises:
            PermissionError: If there is no shared key created prior to
                attempting to encrypt
        """
        if (self._shared_secret is None):
            raise PermissionError("No shared key generated yet")

        cipher_object = self._aead_class(self._shared_secret)
        return cipher_object.decrypt(nonce, cipher, self._ad)

    def __increment_nonce(self):
        self._nonce = bytes([sum(self._nonce, self._nonce_increment)])
        len_diff = self._nonce_len - len(self._nonce)
        self._nonce = b"\0" * len_diff + self._nonce
