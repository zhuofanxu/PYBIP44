# -*- coding: utf-8 -*-

from . import chain_public_key
from . import chain_private_key

class ChainManager(object):

    @staticmethod
    def get_chain_publickey_class(chain_name):
        """ Get special publickey class by chain name

        Args:
            chain_name (str): chain name, eg: btc

        Returns:
            special publickey class
        """
        if not isinstance(chain_name, str):
            raise TypeError("Parameter chain_type must be a str type")

        special_class_name =  chain_name.upper() + 'PublicKey'
        special_class = getattr(chain_public_key, special_class_name, None)

        if special_class is None:
            raise TypeError("Not support chain name")
        
        return special_class

    @staticmethod
    def get_chain_privatekey_class(chain_name):
        """ Get special privatekey class by chain name

        Args:
            chain_name (str): chain name, eg: btc

        Returns:
            special privatekey class
        """
        if not isinstance(chain_name, str):
            raise TypeError("Parameter chain_type must be a str type")

        special_class_name =  chain_name.upper() + 'PrivateKey'
        special_class = getattr(chain_private_key, special_class_name, None)

        if special_class is None:
            raise TypeError("Not support chain name")
        
        return special_class