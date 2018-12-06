# -*- coding: utf-8 -*-

from two1.bitcoin.utils import rand_bytes
from .hd_key import HDKey, HARDENED_HEXA
from .hd_public_key import HDPublicKey
from pybip44.chain_manager import ChainManager
from pybip44.utils import hashlib, hmac, get_bytes, Mnemonic

class HDPrivateKey(HDKey):

    def __init__(self, key, chain_code, index, depth, chain_name, parent_fingerprint=b'\x00\x00\x00\x00'):
        if index < 0 or index > 0xffffffff:
            raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

        private_key_class = ChainManager.get_chain_privatekey_class(chain_name)
        private_key = private_key_class(key)
        self.chain_name = chain_name

        HDKey.__init__(self, private_key, chain_code, index, depth, parent_fingerprint)
        self._public_key = None

    def __int__(self):
        return int(self._key)

    def to_hex(self):
        return self._key.to_hex()

    @property
    def identifier(self):
        """ Returns the identifier for the key.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        In this case, it will return the RIPEMD-160 hash of the
        corresponding public key.

        Returns:
            bytes: A 20-byte RIPEMD-160 hash.
        """
        return self.public_key.identifier

    @property
    def public_key(self):
        """ Returns the public key associated with this private key.

        Returns:
            HDPublicKey:
                The HDPublicKey object that corresponds to this
                private key.
        """
        if self._public_key is None:
            # print(self.parent_fingerprint)
            self._public_key = HDPublicKey(
                public_key=self._key.public_key,
                chain_code=self.chain_code,
                index=self.index,
                depth=self.depth,
                parent_fingerprint=self.parent_fingerprint
            )

        return self._public_key

    @staticmethod
    def master_key_from_mnemonic(mnemonic, chain_name, passphrase=''):
        """ Generates a master key from a mnemonic.

        Args:
            mnemonic (str): The mnemonic sentence representing
               the seed from which to generate the master key.
            passphrase (str): Password if one was used.

        Returns:
            HDPrivateKey: the master private key.
        """
        seed = Mnemonic.to_seed(mnemonic, passphrase)
        return HDPrivateKey.master_key_from_seed(seed, chain_name)

    @staticmethod
    def master_key_from_seed(seed, chain_name):
        """ Generates a master key from a provided seed.

        Args:
            seed (bytes or str): a string of bytes or a hex string

        Returns:
            HDPrivateKey: the master private key.
        """
        public_key_class = ChainManager.get_chain_publickey_class(chain_name)
        curve_g_n = public_key_class.curve_g_n
        bytes_seed_name = public_key_class.bytes_seed_name

        S = get_bytes(seed)
        I = hmac.new(bytes_seed_name, S, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]
        parse_Il = int.from_bytes(Il, 'big')
        if parse_Il == 0 or parse_Il >= curve_g_n:
            raise ValueError("Bad seed, resulting in invalid key!")

        return HDPrivateKey(key=parse_Il, chain_code=Ir, index=0, depth=0, chain_name=chain_name)

    @staticmethod
    def master_key_from_entropy(chain_name, passphrase='', strength=128):
        """ Generates a master key from system entropy.

        Args:
            strength (int): Amount of entropy desired. This should be
               a multiple of 32 between 128 and 256.
            passphrase (str): An optional passphrase for the generated
               mnemonic string.

        Returns:
            HDPrivateKey, str:
                a tuple consisting of the master
                private key and a mnemonic string from which the seed
                can be recovered.
        """
        if strength % 32 != 0:
            raise ValueError("strength must be a multiple of 32")
        if strength < 128 or strength > 256:
            raise ValueError("strength should be >= 128 and <= 256")
        entropy = rand_bytes(strength // 8)
        m = Mnemonic(language='english')
        n = m.to_mnemonic(entropy)
        return HDPrivateKey.master_key_from_seed(
            Mnemonic.to_seed(n, passphrase), chain_name=chain_name), n

    @staticmethod
    def from_parent(parent_key, i):
        """ Derives a child private key from a parent
        private key. It is not possible to derive a child
        private key from a public parent key.

        Args:
            parent_private_key (HDPrivateKey):
        """
        if not isinstance(parent_key, HDPrivateKey):
            raise TypeError("parent_key must be an HDPrivateKey object.")

        curve_g_n = parent_key._key.public_key.curve_g_n

        hmac_key = parent_key.chain_code
        if i & HARDENED_HEXA:
            hmac_data = b'\x00' + bytes(parent_key._key) + i.to_bytes(length=4, byteorder='big')
        else:
            hmac_data = parent_key.public_key.compressed_bytes + i.to_bytes(length=4, byteorder='big')

        I = hmac.new(hmac_key, hmac_data, hashlib.sha512).digest()
        Il, Ir = I[:32], I[32:]

        parse_Il = int.from_bytes(Il, 'big')
        if parse_Il >= curve_g_n:
            return None

        child_key = (parse_Il + parent_key._key.key) % curve_g_n

        if child_key == 0:
            # Incredibly unlucky choice
            return None

        child_depth = parent_key.depth + 1
        return HDPrivateKey(
            key=child_key,
            chain_code=Ir,
            index=i,
            depth=child_depth,
            chain_name=parent_key.chain_name,
            parent_fingerprint=parent_key.fingerprint
        )
