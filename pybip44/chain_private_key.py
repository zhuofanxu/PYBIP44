# -*- coding: utf-8 -*-
"""
Description:
    PrivateKey for special chain
    support BTC ETH... with secp256k1 curve and NEO/ONT... with secp256r1 curve
"""

from neocore import KeyPair
from .hdkeys import PrivateKey
from .chain_public_key import BTCPublicKey, ETHPublicKey, NEOPublicKey, ONTPublicKey

class BTCPrivateKey(PrivateKey):
    
    @property
    def public_key(self):
        if self._public_key is None:
            self._public_key = BTCPublicKey.from_point(BTCPublicKey.curve.public_key(self.key))
        return self._public_key


class ETHPrivateKey(BTCPrivateKey):

    @property
    def public_key(self):
        if self._public_key is None:
            self._public_key = ETHPublicKey.from_point(BTCPublicKey.curve.public_key(self.key))
        return self._public_key


class NEOPrivateKey(PrivateKey):

    @property
    def public_key(self):
        if self._public_key is None:
            keypair = KeyPair.KeyPair(bytes(self))
            self._public_key = NEOPublicKey.from_point(keypair.PublicKey)
        return self._public_key


class ONTPrivateKey(NEOPrivateKey):

    @property
    def public_key(self):
        if self._public_key is None:
            keypair = KeyPair.KeyPair(bytes(self))
            self._public_key = ONTPublicKey.from_point(keypair.PublicKey)
        return self._public_key