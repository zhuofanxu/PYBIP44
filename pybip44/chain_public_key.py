# -*- coding: utf-8 -*-
"""
Description:
    PublicKey for special chain
    support BTC ETH... with secp256k1 curve and NEO/ONT... with secp256r1 curve
"""
from two1.crypto.ecdsa import secp256k1, ECPointAffine
from neocore.Cryptography.Crypto import Crypto
from eth_utils import encode_hex
from .hdkeys import PublicKey
from .utils import binascii, hashlib, base58

class BTCPublicKey(PublicKey):
    
    curve = secp256k1()
    curve_g_n = curve.n
    bytes_seed_name = b"Bitcoin seed"
    TESTNET_VERSION = 0x6F
    MAINNET_VERSION = 0x00

    def __init__(self, x, y):
        p = ECPointAffine(self.curve, x, y)

        if not self.curve.is_on_curve(p):
            raise ValueError("The provided (x, y) are not on the secp256k1 curve.")

        self.point = p
        super().__init__()

    def __bytes__(self):
        return bytes(self.point)

    def address(self, compressed=True):
        version = bytes([self.MAINNET_VERSION])
        ripe = self.hash160(compressed)
        checksum = hashlib.sha256(hashlib.sha256(version + ripe).digest()).digest()[:4]
        return base58.b58encode(version + ripe + checksum).decode('utf-8')

    @property
    def compressed_bytes(self):
        return self.point.compressed_bytes

    @staticmethod
    def from_point(point):
        return BTCPublicKey(point.x, point.y)


class ETHPublicKey(BTCPublicKey):

    def address(self, compressed=True):
        return encode_hex(self.keccak[12:])

    @staticmethod
    def from_point(point):
        return ETHPublicKey(point.x, point.y)


class NEOPublicKey(PublicKey):

    curve_g_n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    bytes_seed_name = b"Nist256p1 seed"

    def __init__(self, point):
        self.point = point
        super().__init__()
        # self.curve = self.point.curve

    def __bytes__(self):
        """Byte string corresponding to a uncompressed representation
        of this public key.

        Returns:
            bytes_bin (bytes): A 65-byte long byte string.
        """
        bytes_hexlify = self.point.encode_point(False)
        bytes_bin = binascii.unhexlify(bytes_hexlify)
        return bytes_bin

    def address(self, compressed=True):
        script = b'21' + self.point.encode_point(compressed) + b'ac'
        script_hash = Crypto.ToScriptHash(script)
        address = Crypto.ToAddress(script_hash)
        return address

    @property
    def compressed_bytes(self):
        """ Byte string corresponding to a compressed representation
        of this public key.

        Returns:
            bytes_bin (bytes): A 33-byte long byte string.
        """
        
        bytes_hexlify = self.point.encode_point(True)
        bytes_bin = binascii.unhexlify(bytes_hexlify)
        return bytes_bin

    @staticmethod
    def from_point(point):
        return NEOPublicKey(point)

class ONTPublicKey(NEOPublicKey):
    
    @staticmethod
    def from_point(point):
        return ONTPublicKey(point)