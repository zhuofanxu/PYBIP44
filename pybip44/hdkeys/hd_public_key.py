# -*- coding: utf-8 -*-

from .hd_key import HDKey, HARDENED_HEXA

class HDPublicKey(HDKey):

    def __init__(self, public_key, chain_code, index, depth,
                 parent_fingerprint=b'\x00\x00\x00\x00'):

        HDKey.__init__(self, public_key, chain_code, index, depth, parent_fingerprint)

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            b (bytes): A 33-byte long byte string.
        """
        return self._key.compressed_bytes

    @property
    def identifier(self):
        """ Returns the identifier for the key.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        In this case, it will return the RIPEMD-160 hash of the
        non-extended public key.

        Returns:
            bytes: A 20-byte RIPEMD-160 hash.
        """
        return self._key.hash160(True)

    @property
    def address(self, compressed=True):
        return self._key.address(compressed)

    def to_hex(self, compressed=True):
        return self._key.to_hex(compressed)

    @staticmethod
    def from_parent(parent_key, i):
        pass