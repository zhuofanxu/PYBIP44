BTC Ethereum NEO ONT BIP44 Python
================================

## Reference resources:
* [ethereum-bip44-python](https://github.com/michailbrynard/ethereum-bip44-python)
* [bip-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
* [iancoleman-bip39](https://iancoleman.io/bip39/)
* [ontology-java-sdk](https://github.com/ontio/ontology-java-sdk)


## Requirements
Python version:  3.6  

Install dependence packages: 
```shell 
pip install -r requirements.txt
```


## Usage
master key creation from system entropy
```python
from pybip44 import HDPrivateKey
master_key, mnemonic = HDPrivateKey.master_key_from_entropy()
print('BIP32 Wallet Generated.')
print('Mnemonic Secret: ' + mnemonic)
```
BTC
```python
master_key = HDPrivateKey.master_key_from_mnemonic('your mnemonic', 'btc')
root_key = HDPrivateKey.from_path(master_key,"m/44'/0'/0'")
```
ETH
```python
master_key = HDPrivateKey.master_key_from_mnemonic('your mnemonic', 'eth')
root_key = HDPrivateKey.from_path(master_key,"m/44'/60'/0'")
```
NEO
```python
master_key = HDPrivateKey.master_key_from_mnemonic('your mnemonic', 'neo')
root_key = HDPrivateKey.from_path(master_key,"m/44'/888'/0'")
```
ONT
```python
master_key = HDPrivateKey.master_key_from_mnemonic('your mnemonic', 'ont')
root_key = HDPrivateKey.from_path(master_key,"m/44'/1024'/0'")
```
### Comman Accounts creation
```python
for i in range(10):
    print("Index %s:" % i)

    hd_private_key = HDPrivateKey.from_path(root_key,'{change}/{index}'.format(change=0, index=i))
    print("private key int：", int(hd_private_key))
    print("private key hex：", hd_private_key.to_hex())

    hd_public_key = hd_private_key.public_key
    print("public key：", hd_public_key.to_hex(compressed=True))
    print("address：" + hd_public_key.address)
```