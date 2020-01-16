'''
#markdown
![](/files/programmingwallet.png)
#endmarkdown
#markdown
![](/files/session1/s1.png)
#endmarkdown
#markdown
# Session 1 Objectives
* Learn pay-to-witness-pubkey-hash
* Learn bech32 addresses
* Redeem a pay-to-witness-pubkey-hash output
#endmarkdown
#markdown
# Pay to Witness Pubkey Hash (p2wpkh)
#endmarkdown
#markdown
## What is Segregated Witness?
* A way to fix transaction malleability
* A way to reduce network transmission
* A way to increase transaction throughput
* A way for smooth future upgrades
#endmarkdown
#markdown
## p2pkh
![](/files/session1/old.png)
#endmarkdown
#markdown
## p2wpkh
![](/files/session1/new.png)
#endmarkdown
#markdown
## Pay to Witness Pubkey Hash (aka "Native Segwit")
* Acts like p2pkh but puts the ScriptSig data in another place
* New type of ScriptPubKey
* Different Data is sent to pre-Segwit nodes vs Segwit nodes
#endmarkdown
#markdown
# Non-Segwit Nodes
![](/files/session1/old-nodes.png)
#endmarkdown
#markdown
# Segwit Nodes
![](/files/session1/new-nodes.png)
#endmarkdown
#code
>>> import ecc, script, tx

#endcode
#unittest
tx:TxTest:test_parse_segwit:
#endunittest
#unittest
tx:TxTest:test_serialize_segwit:
#endunittest
#markdown
## Combining Scripts
* ScriptPubKey:
![](/files/session1/p2wpkh-scriptpubkey.png)
* ScriptSig:
Empty!
#endmarkdown
#markdown
## Combined
![](/files/session1/p2wpkh-combined.png)
#endmarkdown
#code
>>> from IPython.display import YouTubeVideo
>>> YouTubeVideo('ZHtJYfZsiAE')

#endcode
#markdown
## Witness
![](/files/session1/p2wpkh-witness.png)
#endmarkdown
#markdown
## BIP143: New Signature Hash for Segwit
* Solve quadratic hashing
* Input amounts included
* Precompute and reuse parts
#endmarkdown
#markdown
# Legacy Signature Hash Spec
* Version
* For each input: UTXO location/ScriptPubKey for input being signed/Sequence
* For each output: Amount and ScriptPubKey
* Locktime
* Hashing Type (SIGHASH_ALL, usually)
#endmarkdown
#markdown
# Witness
![](/files/session1/p2wpkh-witness.png)
#endmarkdown
#markdown
# Segwit Signature Hash Spec (BIP143)
* Version
* HashPrevouts (from TX hashes and indices of all inputs)
* HashSequence (from sequences of all inputs)
* Script Code
* Input Specific: value in Satoshis and sequence
* HashOutputs (from amount and ScriptPubKey of all outputs)
* Locktime
* Hashing Type (SIGHASH_ALL, usually)
#endmarkdown
#markdown
## Script Code
* ScriptPubKey being executed
* For p2wpkh, this is the p2pkh ScriptPubKey
* The 2nd argument is used as the hash
#endmarkdown
#unittest
tx:TxTest:test_sig_hash_bip143:
#endunittest
#markdown
# Bech32
#endmarkdown
#markdown
### Problems with Base58
* Encoding/Decoding is slow
* Inefficient for QR codes
* Hard to communicate in analog effectively
* Hash256 checksum is slow and has no error-detection
* Error-Detection requires a power of 2, 58 is not
#endmarkdown
#markdown
### Bech32
* Defined in BIP173
* Uses BoseChaudhuriHocquenghem, or BCH Code, hence "Bech"
* 32 characters, using only lower case letters and numbers
* All characters (26+10) except 1, b, i, o
* NOT ALPHABETICAL
* Address has human part, separator, data and checksum
#endmarkdown
#markdown
# Bech32 Address
![](/files/session1/bech32.png)
#endmarkdown
#markdown
### Human Part
* bc = mainnet, tb = testnet

### Separator
* 1

### Data Part
* First character is the Segwit Version (0)
* Rest is data (usually a hash) of 1 to 40 bytes

#endmarkdown
#markdown
# Data Part
![](/files/session1/segwitaddress.png)
#endmarkdown
#code
>>> # example for creating a bech32 address
>>> from ecc import S256Point
>>> from helper import encode_bech32_checksum, encode_varstr
>>> sec_hex = '039d5ca49670cbe4c3bfa84c96a8c87df086c6ea6a24ba6b809c9de234496808d5'
>>> point = S256Point.parse(bytes.fromhex(sec_hex))
>>> h160 = point.hash160()
>>> raw = bytes([0])
>>> raw += encode_varstr(h160)
>>> bech32 = encode_bech32_checksum(raw, testnet=False)
>>> print(bech32)
bc1qttnpu7attc248hz22jxtyaqkfc7z4qd8yk882v

#endcode
#exercise
#### Create a testnet bech32 address using your private key from the Session 0

Fill in the spreadsheet with your bech32 address.
---
>>> from ecc import PrivateKey
>>> from helper import encode_bech32_checksum, encode_varstr, hash256, little_endian_to_int
>>> # use the same passphrase from session 0
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # create a private key using the secret
>>> private_key = PrivateKey(secret)  #/
>>> # get the public key using the .point property
>>> public_key = private_key.point  #/
>>> # get the hash160 of the point
>>> h160 = public_key.hash160()  #/
>>> # the raw bytes to be encrypted starts with the segwit version (0 or b'\x00)
>>> raw = bytes([0])  #/
>>> # next, add the hash160 using encode_varstr
>>> raw += encode_varstr(h160)  #/
>>> # encode to bech32 using encode_bech32_checksum, remember testnet=True
>>> bech32 = encode_bech32_checksum(raw, testnet=True)  #/
>>> # print the address
>>> print(bech32)  #/
tb1qgqd0pdtu0f9hfyx9pzj86p686q70dtpwkmp0yw

#endexercise
#unittest
ecc:S256Test:test_bech32_address:
#endunittest
#markdown
## Signing a p2wpkh Input
* ScriptSig is empty!
* Witness field has the signature and the compressed SEC pubkey
![](/files/session1/p2wpkh-witness.png)
#endmarkdown
#code
>>> # Example for signing a p2wpkh input
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int, SIGHASH_ALL
>>> from tx import Tx
>>> from witness import Witness
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> raw_tx_hex = '01000000000101cca99b60e1d687e8faaf93e114114e7b5f6382d9f5d45ffb76ac7472ad7d734c0100000000ffffffff014c400f0000000000160014092ab91b37b4182061d9c01199aaac029f89561f0000000000'
>>> input_index = 0
>>> stream = BytesIO(bytes.fromhex(raw_tx_hex))
>>> tx_obj = Tx.parse(stream, testnet=True)
>>> z = tx_obj.sig_hash_bip143(input_index)
>>> der = private_key.sign(z).der()
>>> sig = der + SIGHASH_ALL.to_bytes(1, 'big')
>>> sec = private_key.point.sec()
>>> tx_in = tx_obj.tx_ins[input_index]
>>> tx_in.witness = Witness([sig, sec])
>>> print(tx_obj.verify_input(input_index))
True

#endcode
#unittest
tx:TxTest:test_sign_p2wpkh:
#endunittest
#code
>>> # Example for creating a p2wpkh transaction
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from script import P2WPKHScriptPubKey
>>> from tx import Tx, TxIn, TxOut
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> prev_tx_hex = '0f007db8670c8b22ed64d95c61895d9c8e516ec938f99fbe4973fc0172ef93cf'
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> prev_index = 1
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> amount = tx_in.value(testnet=True) - fee
>>> target_address = 'tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au'
>>> _, _, h160 = decode_bech32(target_address)
>>> script_pubkey = P2WPKHScriptPubKey(h160)
>>> tx_out = TxOut(amount, script_pubkey)
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
>>> tx_obj.sign_input(0, private_key)
True
>>> print(tx_obj.serialize().hex())
01000000000101cf93ef7201fc7349be9ff938c96e518e9c5d89615cd964ed228b0c67b87d000f0100000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7502483045022100e606e37820fd935e29955b3d03935beb1fca64922029634f4e1024fbe14bbc950220748ab6bc06054dd422039e9587566d5968faa9f39810d2194a9bcf18b6c092f3012102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d00000000

#endcode
#exercise

#### Create a p2wpkh spending transaction

You have been sent 0.05 testnet BTC. Send 0.03 to `tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au`
and the change back to your bech32 address.
---
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from network import SimpleNode
>>> from script import P2WPKHScriptPubKey
>>> from tx import Tx, TxIn, TxOut
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> private_key = PrivateKey(little_endian_to_int(hash256(passphrase)))
>>> prev_tx_hex = '94448a601fce6961a5fabbc554068460d979b15bee9531e378fbb458bc644378'  #/prev_tx_hex = '<fill this in>'
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> prev_index = 0  #/prev_index = -1  # fill this in
>>> fee = 500
>>> target_address = 'tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au'
>>> target_amount = 3000000
>>> # create the transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # create an array of tx_outs
>>> tx_outs = []  #/
>>> # decode the target address to get the hash160 of the address
>>> _, _, target_h160 = decode_bech32(target_address)  #/
>>> # create the target script pubkey using P2WPKHScriptPubKey
>>> target_script_pubkey = P2WPKHScriptPubKey(target_h160)  #/
>>> # add the target transaction output
>>> tx_outs.append(TxOut(target_amount, target_script_pubkey))
>>> # calculate the change amount, remember you were sent 5000000 sats
>>> change_amount = 5000000 - target_amount - fee  #/
>>> # calculate the hash160 for your private key
>>> change_h160 = private_key.point.hash160()  #/
>>> # create the change script pubkey using P2WPKHScriptPubKey
>>> change_script_pubkey = P2WPKHScriptPubKey(change_h160)  #/
>>> tx_outs.append(TxOut(change_amount, change_script_pubkey))  #/
>>> # create the transaction with testnet=True and segwit=True
>>> tx_obj = Tx(1, [tx_in], tx_outs, 0, testnet=True, segwit=True)  #/
>>> # sign the one input with your private key
>>> tx_obj.sign_input(0, private_key)  #/
True
>>> # print the hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
01000000000101784364bc58b4fb78e33195ee5bb179d960840654c5bbfaa56169ce1f608a44940000000000ffffffff02c0c62d00000000001600146e13971913b9aa89659a9f53d327baa8826f2d758c821e0000000000160014401af0b57c7a4b7490c508a47d0747d03cf6ac2e02483045022100ace4ba51b732f7098771cf9e6aee2abc03b1c20de01af54dd7e9463f702255d802205911108195c7fc30eab6192cacefa8fe3d4e3b123def84b65ecba399de5851dd012102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d00000000

#endexercise
#unittest
tx:TxTest:test_verify_p2wpkh:
#endunittest
#markdown
## What is P2SH-P2WPKH?
* Backwards-compatible p2wpkh
* Uses p2sh to wrap single-key segwit (p2wpkh)
* Looks like p2sh addresses which start with a 3
#endmarkdown
#markdown
![](/files/session1/p2sh-p2wpkh-old.png)
#endmarkdown
#markdown
![](/files/session1/p2sh-p2wpkh-new.png)
#endmarkdown
#markdown
# P2SH-P2WPKH "Nested Segwit"
* Acts like p2wpkh but looks like p2sh
* ScriptPubKey looks exactly like p2sh
* Different Data is sent to pre-Segwit nodes vs Segwit nodes
#endmarkdown
#markdown
# Non-Segwit Nodes
![](/files/session1/p2sh-p2wpkh-old-nodes.png)
#endmarkdown
#markdown
# Segwit Nodes
![](/files/session1/p2sh-p2wpkh-new-nodes.png)
#endmarkdown
#markdown
## Combining Scripts
* ScriptPubKey:
![](/files/session1/p2sh-p2wpkh-scriptpubkey.png)
* ScriptSig:
![](/files/session1/p2sh-p2wpkh-scriptsig.png)
#endmarkdown
#markdown
## Combined
![](/files/session1/p2sh-p2wpkh-combined.png)
#endmarkdown
#markdown
## RedeemScript
![](/files/session1/p2sh-p2wpkh-redeemscript.png)
#endmarkdown
#markdown
## Witness
![](/files/session1/p2sh-p2wpkh-witness.png)
#endmarkdown
#code
>>> from IPython.display import YouTubeVideo
>>> YouTubeVideo('efDU3HZAHtc')

#endcode
#markdown
### Generating a p2sh-p2wpkh address
* RedeemScript is what would be the ScriptPubKey for p2wpkh
* This is Segwit Version + 20 byte hash
* p2sh address is the hash160 of the RedeemScript in Base58
#endmarkdown
#code
>>> # Example of generating a p2sh-p2wpkh address
>>> from ecc import S256Point
>>> from helper import encode_base58_checksum, hash160
>>> from script import P2WPKHScriptPubKey, P2SHScriptPubKey
>>> sec_hex = '02c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d'
>>> point = S256Point.parse(bytes.fromhex(sec_hex))
>>> h160 = point.hash160()
>>> redeem_script = P2WPKHScriptPubKey(h160)
>>> p2sh_h160 = hash160(redeem_script.raw_serialize())
>>> p2sh_script_pubkey = P2SHScriptPubKey(p2sh_h160)
>>> address = p2sh_script_pubkey.address(testnet=False)
>>> print(address)
3CobPD6RBnTZsFdka71XHQr4vHXDZMu2zm

#endcode
#exercise
#### Create a testnet p2sh-p2wpkh address with your private key.

---
>>> from ecc import PrivateKey
>>> from helper import encode_varstr, hash160, hash256, little_endian_to_int
>>> from script import P2WPKHScriptPubKey, P2SHScriptPubKey
>>> # use the same passphrase from session 0
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # create a private key using the secret
>>> private_key = PrivateKey(secret)  #/
>>> # get the public key using the .point property
>>> public_key = private_key.point  #/
>>> # get the hash160 of the point
>>> h160 = public_key.hash160()  #/
>>> # create the RedeemScript, which is the P2WPKHScriptPubKey of the hash160
>>> redeem_script = P2WPKHScriptPubKey(h160)  #/
>>> # perform a hash160 on the raw serialization of the RedeemScript
>>> p2sh_h160 = hash160(redeem_script.raw_serialize())  #/
>>> # create a P2SHScriptPubKey using the h160
>>> p2sh_script = P2SHScriptPubKey(p2sh_h160)  #/
>>> # return the address, remember testnet=True
>>> address = p2sh_script.address(testnet=True)  #/
>>> # print the address
>>> print(address)  #/
2N4MoSx2SoExv53GJFEdPuMqL8djPQPH2er

#endexercise
#unittest
script:P2SHScriptPubKeyTest:test_address:
#endunittest
#unittest
ecc:S256Test:test_p2sh_p2wpkh_address:
#endunittest
#markdown
### Signing a p2sh-p2wpkh input
* ScriptSig is only the RedeemScript
* RedeemScript is what would be the ScriptPubKey for p2wpkh
* Witness is the signature and compressed SEC pubkey
#endmarkdown
#code
>>> # Example for signing a p2sh-p2wpkh input
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int, SIGHASH_ALL
>>> from script import Script
>>> from tx import Tx
>>> from witness import Witness
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
>>> raw_tx_hex = '010000000001014e6b786f3cd70ab1ffd75caa6bb252c9888fdca9ca94d40fec24bec3e643d89e0000000000ffffffff014c400f0000000000160014401af0b57c7a4b7490c508a47d0747d03cf6ac2e0000000000'
>>> input_index = 0
>>> stream = BytesIO(bytes.fromhex(raw_tx_hex))
>>> tx_obj = Tx.parse(stream, testnet=True)
>>> z = tx_obj.sig_hash_bip143(input_index, redeem_script=redeem_script)
>>> der = private_key.sign(z).der()
>>> sig = der + SIGHASH_ALL.to_bytes(1, 'big')
>>> sec = private_key.point.sec()
>>> tx_in = tx_obj.tx_ins[input_index]
>>> tx_in.witness = Witness([sig, sec])
>>> tx_in.script_sig = Script([redeem_script.raw_serialize()])
>>> print(tx_obj.verify_input(input_index))
True

#endcode
#unittest
tx:TxTest:test_sign_p2sh_p2wpkh:
#endunittest
#code
>>> # Example for creating a p2sh-p2wpkh transaction
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from script import P2WPKHScriptPubKey
>>> from tx import Tx, TxIn, TxOut
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> prev_tx_hex = '6c14a8370da20c7de5ebf216ece3156e99e7d6070442d93b80cdc344b2e80867'
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> prev_index = 1
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> amount = tx_in.value(testnet=True) - fee
>>> target_address = 'tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au'
>>> _, _, h160 = decode_bech32(target_address)
>>> script_pubkey = P2WPKHScriptPubKey(h160)
>>> tx_out = TxOut(amount, script_pubkey)
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
>>> redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
>>> tx_obj.sign_input(0, private_key, redeem_script=redeem_script)
True
>>> print(tx_obj.serialize().hex())
010000000001016708e8b244c3cd803bd9420407d6e7996e15e3ec16f2ebe57d0ca20d37a8146c0100000017160014401af0b57c7a4b7490c508a47d0747d03cf6ac2effffffff0198801e00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7502483045022100e92c1dc1066c1614da514d0e4e97feb8aec96d88598d9b2f9e7840948dfd353f02201fe146c5ec7af8a9a22faed1726f527a6d1c4cf2243476f10637241e2f98f7af012102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d00000000

#endcode
#exercise

#### Create a p2sh-p2wpkh spending transaction

You have been sent 0.05 testnet BTC. Send 0.03 to `tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au`
and the change back to your p2sh-p2wpkh address.
---
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, decode_base58, hash256, little_endian_to_int
>>> from network import SimpleNode
>>> from script import P2WPKHScriptPubKey, P2SHScriptPubKey
>>> from tx import Tx, TxIn, TxOut
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> private_key = PrivateKey(little_endian_to_int(hash256(passphrase)))
>>> prev_tx_hex = '9b3e6e253c79672a4e60a8a563ee735c8f87351058a7a0f5d53a2b5771cf6a6d'  #/prev_tx_hex = '<fill this in>'
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> prev_index = 0  #/prev_index = -1  # fill this in
>>> fee = 500
>>> target_address = 'tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au'
>>> target_amount = 3000000
>>> # create the transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # create an array of tx_outs
>>> tx_outs = []  #/
>>> # decode the target address to get the hash160 of the address
>>> _, _, target_h160 = decode_bech32(target_address)  #/
>>> # create the target script pubkey using P2WPKHScriptPubKey
>>> target_script_pubkey = P2WPKHScriptPubKey(target_h160)  #/
>>> # add the target transaction output
>>> tx_outs.append(TxOut(target_amount, target_script_pubkey))
>>> # calculate the change amount, remember you were sent 5000000 sats
>>> change_amount = 5000000 - target_amount - fee  #/
>>> # get the p2sh-p2wpkh address for using your private key
>>> p2sh_address = private_key.point.p2sh_p2wpkh_address()  #/
>>> # get the hash160 by decoding the p2sh-p2wpkh address
>>> change_h160 = decode_base58(p2sh_address)
>>> # create the change script pubkey using P2SHScriptPubKey
>>> change_script_pubkey = P2SHScriptPubKey(change_h160)  #/
>>> tx_outs.append(TxOut(change_amount, change_script_pubkey))  #/
>>> # create the transaction with testnet=True and segwit=True
>>> tx_obj = Tx(1, [tx_in], tx_outs, 0, testnet=True, segwit=True)  #/
>>> # grab the RedeemScript from the public point
>>> redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()  #/
>>> # sign the one input with your private key
>>> tx_obj.sign_input(0, private_key, redeem_script=redeem_script)  #/
True
>>> # print the hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
010000000001016d6acf71572b3ad5f5a0a7581035878f5c73ee63a5a8604e2a67793c256e3e9b0000000017160014401af0b57c7a4b7490c508a47d0747d03cf6ac2effffffff02c0c62d00000000001600146e13971913b9aa89659a9f53d327baa8826f2d758c821e000000000017a91479e7cf6859a7047b099a078a8ffbbb58b73b8633870247304402205e35a2329e08e949d16189b213586feee2df37a48f961808372bbee44fcbc59402207a66acbd49f1366ff8e5a718d9f4d33867fe4c595b4834822fb6b33e7e99ab98012102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d00000000

#endexercise
'''


from unittest import TestCase

from ecc import S256Point
from helper import (
    encode_bech32_checksum,
    encode_varint,
    encode_varstr,
    hash256,
    int_to_byte,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    read_varstr,
    SIGHASH_ALL,
)
from script import P2PKHScriptPubKey, SegwitPubKey, Script
from tx import Tx, TxIn, TxOut
from witness import Witness


def bech32_address(self, testnet=False):
    raw = b'\x00'
    raw += encode_varstr(self.hash160())
    return encode_bech32_checksum(raw, testnet)


def p2sh_p2wpkh_redeem_script(self):
    from script import P2WPKHScriptPubKey
    return P2WPKHScriptPubKey(self.hash160()).redeem_script()


def p2sh_p2wpkh_address(self, testnet=False):
    redeem_script = self.p2sh_p2wpkh_redeem_script()
    return redeem_script.address(testnet)


def p2sh_address(self, testnet=False):
    # get the RedeemScript equivalent and get its address
    return self.redeem_script().address(testnet)


@classmethod
def parse_segwit(cls, s, testnet=False):
    version = little_endian_to_int(s.read(4))
    marker = s.read(2)
    if marker != b'\x00\x01':
        raise RuntimeError('Not a segwit transaction {}'.format(marker))
    num_inputs = read_varint(s)
    inputs = []
    for _ in range(num_inputs):
        inputs.append(TxIn.parse(s))
    num_outputs = read_varint(s)
    outputs = []
    for _ in range(num_outputs):
        outputs.append(TxOut.parse(s))
    for tx_in in inputs:
        tx_in.witness = Witness.parse(s)
    locktime = little_endian_to_int(s.read(4))
    return cls(version, inputs, outputs, locktime, testnet=testnet, segwit=True)


def serialize_segwit(self):
    result = int_to_little_endian(self.version, 4)
    result += b'\x00\x01'
    result += encode_varint(len(self.tx_ins))
    for tx_in in self.tx_ins:
        result += tx_in.serialize()
    result += encode_varint(len(self.tx_outs))
    for tx_out in self.tx_outs:
        result += tx_out.serialize()
    for tx_in in self.tx_ins:
        result += tx_in.witness.serialize()
    result += int_to_little_endian(self.locktime, 4)
    return result


def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
    tx_in = self.tx_ins[input_index]
    s = int_to_little_endian(self.version, 4)
    s += self.hash_prevouts() + self.hash_sequence()
    s += tx_in.prev_tx[::-1]
    s += int_to_little_endian(tx_in.prev_index, 4)
    if redeem_script:
        h160 = redeem_script.commands[1]
        script_code = P2PKHScriptPubKey(h160)
    else:
        script_pubkey = tx_in.script_pubkey(self.testnet)
        h160 = script_pubkey.commands[1]
        script_code = P2PKHScriptPubKey(h160)
    s += script_code.serialize()
    s += int_to_little_endian(tx_in.value(testnet=self.testnet), 8)
    s += int_to_little_endian(tx_in.sequence, 4)
    s += self.hash_outputs()
    s += int_to_little_endian(self.locktime, 4)
    s += int_to_little_endian(SIGHASH_ALL, 4)
    return int.from_bytes(hash256(s), 'big')


def sign_p2wpkh(self, input_index, private_key):
    sig = self.get_sig_segwit(input_index, private_key)
    sec = private_key.point.sec()
    self.tx_ins[input_index].finalize_p2wpkh(sig, sec)
    return self.verify_input(input_index)


def sign_p2sh_p2wpkh(self, input_index, private_key):
    redeem_script = private_key.point.p2sh_p2wpkh_redeem_script()
    sig = self.get_sig_segwit(input_index, private_key, redeem_script=redeem_script)
    sec = private_key.point.sec()
    self.tx_ins[input_index].finalize_p2wpkh(sig, sec, redeem_script)
    return self.verify_input(input_index)


def get_sig_segwit(self, input_index, private_key, redeem_script=None, witness_script=None):
    z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
    der = private_key.sign(z).der()
    return der + int_to_byte(SIGHASH_ALL)


def check_sig_segwit(self, input_index, point, signature, redeem_script=None, witness_script=None):
    z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
    return point.verify(z, signature)


def finalize_p2wpkh(self, sig, sec, redeem_script=None):
    if redeem_script:
        self.script_sig = Script([redeem_script.raw_serialize()])
    else:
        self.script_sig = Script()
    self.witness = Witness([sig, sec])


class SessionTest(TestCase):

    def test_apply(self):
        S256Point.bech32_address = bech32_address
        S256Point.p2sh_p2wpkh_redeem_script = p2sh_p2wpkh_redeem_script
        S256Point.p2sh_p2wpkh_address = p2sh_p2wpkh_address
        SegwitPubKey.p2sh_address = p2sh_address
        Tx.check_sig_segwit = check_sig_segwit
        Tx.get_sig_segwit = get_sig_segwit
        Tx.parse_segwit = parse_segwit
        Tx.serialize_segwit = serialize_segwit
        Tx.sig_hash_bip143 = sig_hash_bip143
        Tx.sign_p2wpkh = sign_p2wpkh
        Tx.sign_p2sh_p2wpkh = sign_p2sh_p2wpkh
        TxIn.finalize_p2wpkh = finalize_p2wpkh
