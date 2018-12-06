# -*- coding: utf-8 -*-

from two1.bitcoin.utils import bytes_to_str

class PrivateKey(object):
    """ Encapsulation of a Bitcoin ECDSA private key.

    Args:
        k (int): The private key.

    Returns:
        PrivateKey: The object representing the private key.
    """
    def __init__(self, k):
        self.key = k
        self._public_key = None

    def __bytes__(self):
        return self.key.to_bytes(32, 'big')

    def __int__(self):
        return self.key

    def to_hex(self):
        return bytes_to_str(bytes(self))

    @staticmethod
    def from_bytes(b):
        """ Generates PrivateKey from the underlying bytes.

        Args:
            b (bytes): A byte stream containing a 256-bit (32-byte) integer.

        Returns:
            tuple(PrivateKey, bytes): A PrivateKey object and the remainder
            of the bytes.
        """
        if len(b) < 32:
            raise ValueError('b must contain at least 32 bytes')

        return PrivateKey(int.from_bytes(b[:32], 'big'))

    @staticmethod
    def from_hex(h):
        """ Generates PrivateKey from a hex-encoded string.

        Args:
            h (str): A hex-encoded string containing a 256-bit
                 (32-byte) integer.

        Returns:
            PrivateKey: A PrivateKey object.
        """
        return PrivateKey.from_bytes(bytes.fromhex(h))

    @staticmethod
    def from_int(i):
        """ Initializes a private key from an integer.

        Args:
            i (int): Integer that is the private key.

        Returns:
            PrivateKey: The object representing the private key.
        """
        return PrivateKey(i)

    @property
    def public_key(self):
        """ Returns the public key associated with this private key.

        Returns:
            PublicKey:
                The PublicKey object that corresponds to this
                private key.
        """
        raise NotImplementedError