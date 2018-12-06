#-*- coding: utf-8 -*-

from pybip44 import HDPrivateKey

master_key = HDPrivateKey.master_key_from_mnemonic('obscure worry home pass museum toss else accuse limb hover denial alpha', 'ont')
root_key = HDPrivateKey.from_path(master_key,"m/44'/1024'/0'")

for i in range(10):
    print("Index %s:" % i)

    hd_private_key = HDPrivateKey.from_path(root_key,'{change}/{index}'.format(change=0, index=i))
    # print("私钥：", int(hd_private_key))
    print("私钥: " + hd_private_key.to_hex())

    hd_public_key = hd_private_key.public_key
    print("公钥", hd_public_key.to_hex())
    print("地址: " + hd_public_key.address)

master_key = HDPrivateKey.master_key_from_mnemonic('obscure worry home pass museum toss else accuse limb hover denial alpha', 'eth')
root_key = HDPrivateKey.from_path(master_key,"m/44'/60'/0'")
for i in range(10):
    print("Index %s:" % i)

    hd_private_key = HDPrivateKey.from_path(root_key,'{change}/{index}'.format(change=0, index=i))
    # print("私钥：", int(hd_private_key))
    print("私钥: ", hd_private_key.to_hex())

    hd_public_key = hd_private_key.public_key
    print("公钥", hd_public_key.to_hex())
    print("地址: ", hd_public_key.address)