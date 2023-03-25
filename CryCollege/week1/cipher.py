import pytest


def pad_string_to_length(s: bytes, length: int) -> bytes:
    """
    Pad a string to a given length by repeating it.
    """
    if length < len(s):
        raise ValueError("The length must be larger than the string length.")

    return s * (length // len(s)) + s[:length % len(s)]

def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("The two byte strings must have the same length.")

    return bytes([x ^ y for x, y in zip(a, b)])


class XORCipher:

    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        """
        Encrypt the data using the Vigenère cipher
        """
        key = self.key if len(data) <= len(self.key) else pad_string_to_length(self.key, len(data))

        return xor(data, key[:len(data)])

    def decrypt(self, data):
        """
        Decrypt the data using the Vigenère cipher
        """
        return self.encrypt(data)


@pytest.fixture
def xor_cipher():
    key = bytes.fromhex("AB CD EF AFFE AFFE DEADBEEF")
    cipher = XORCipher(key)
    return cipher


def test_xor_enc(xor_cipher):
    res = xor_cipher.encrypt(b"HALLO!")
    assert(res == b'\xe3\x8c\xa3\xe3\xb1\x8e')


def test_xor_dec(xor_cipher):
    res = xor_cipher.decrypt(b'\xe3\x8c\xa3\xe3\xb1\x8e')
    assert(res == b"HALLO!")


def test_xor_equiv(xor_cipher):
    msg = b"dkahsdjkasdhashdahsdha"
    assert(xor_cipher.encrypt(msg) == xor_cipher.decrypt(msg))


def test_shortkey():
    msg = b"a" * 1000
    key = b"1337"

    cipher = XORCipher(key)
    assert cipher.decrypt(cipher.encrypt(msg)) == msg