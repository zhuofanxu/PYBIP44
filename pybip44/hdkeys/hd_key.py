# -*- coding: utf-8 -*-

from pybip44.utils import get_bytes

HARDENED_HEXA = 0x80000000

class HDKey(object):

    def __init__(self, key, chain_code, index, depth, parent_fingerprint):
        if index < 0 or index > 0xffffffff:
            raise ValueError("index is out of range: 0 <= index <= 2**32 - 1")

        if not isinstance(chain_code, bytes):
            raise TypeError("chain_code must be bytes")

        self._key = key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self.parent_fingerprint = get_bytes(parent_fingerprint)

    @property
    def master(self):
        """ Whether or not this is a master node.

        Returns:
            bool: True if this is a master node, False otherwise.
        """
        return self.depth == 0

    @property
    def hardened(self):
        """ Whether or not this is a hardened node.

        Hardened nodes are those with indices >= HARDENED_HEXA.

        Returns:
            bool: True if this is hardened, False otherwise.
        """
        # A hardened key is a key with index >= 2 ** 31, so
        # we check that the MSB of a uint32 is set.
        return self.index & HARDENED_HEXA

    @property
    def fingerprint(self):
        """ Returns the key's fingerprint, which is the first 4 bytes
        of its identifier.

        A key's identifier and fingerprint are defined as:
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers

        Returns:
            bytes: The first 4 bytes of the RIPEMD-160 hash.
        """
        return self.identifier[:4]

    @staticmethod
    def parse_path(path):
        """parse a str path to list  and remove trailing '/'
        """
        if isinstance(path, str):
            p = path.rstrip("/").split("/")
        elif isinstance(path, bytes):
            p = path.decode('utf-8').rstrip("/").split("/")
        else:
            p = list(path)
        return p

    @staticmethod
    def from_path(root_key, path):
        """iterate path and generate extendkey from last extendkey  
        the derive order is
            m/purpose'/coin_type'/account'/change/address_index
            mnemonic->seed->master_key
            root_key = m->purpose'->coin_type'->account'
            address_key = root_key->change_key->index_key
        """
        p = HDKey.parse_path(path)

        if p[0] == "m":
            if root_key.master:
                p = p[1:]
            else:
                raise ValueError("root_key must be a master key if 'm' is the first element of the path.")

        keys = [root_key]
        for i in p:
            if isinstance(i, str):
                hardened = i[-1] == "'"
                index = int(i[:-1], 0) | HARDENED_HEXA if hardened else int(i, 0)
            else:
                index = i
            k = keys[-1]
            klass = k.__class__
            keys.append(klass.from_parent(k, index))
        return keys[-1]