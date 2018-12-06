# -*- coding: utf-8 -*-

import hashlib
from two1.bitcoin.utils import bytes_to_str
from ..utils import sha3

class PublicKey(object):

    def __init__(self):
        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(bytes(self)).digest())
        self.ripe = r.digest()

        r = hashlib.new('ripemd160')
        r.update(hashlib.sha256(self.compressed_bytes).digest())
        self.ripe_compressed = r.digest()

        self.keccak = sha3(bytes(self)[1:])

    def to_hex(self, compressed=True):
        if compressed:
            return bytes_to_str(self.compressed_bytes)
        else:
            return bytes_to_str(bytes(self))

    def hash160(self, compressed=True):
        """ Return the RIPEMD-160 hash of the SHA-256 hash of the
        public key.

        Args:
            compressed (bool): Whether or not the compressed key should
               be used.
        Returns:
            bytes: RIPEMD-160 byte string.
        """
        return self.ripe_compressed if compressed else self.ripe

    def __bytes__(self):
        """for instance bytes convert
        """
        raise NotImplementedError

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): A 33-byte long byte string.
        """
        raise NotImplementedError

    @staticmethod
    def from_point(point):
        """ Generates a public key object from any object
        containing x, y coordinates.

        Args:
            p (Point): An object containing a two-dimensional, affine
               representation of a point on the secp256k1 curve.

        Returns:
            PublicKey: A PublicKey object.
        """
        raise NotImplementedError