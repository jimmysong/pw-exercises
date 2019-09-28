'''
#code
>>> import ecc, script, tx

#endcode
#unittest
tx:TxTest:test_parse_segwit:
#endunittest
#unittest
tx:TxTest:test_serialize_segwit:
#endunittest
#unittest
tx:TxTest:test_sig_hash_bip143:
#endunittest
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
#code
>>> # Example for signing a p2wpkh input
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int, SIGHASH_ALL
>>> from tx import Tx
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
>>> tx_in.witness = [sig, sec]
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
tx:TxTest:test_verify_p2sh_p2wpkh:
#endunittest
#code
>>> # Example of generating a p2sh-p2wpkh address
>>> from ecc import S256Point
>>> from helper import encode_base58_checksum, hash160, h160_to_p2sh_address
>>> from script import P2WPKHScriptPubKey
>>> sec_hex = '02c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d'
>>> point = S256Point.parse(bytes.fromhex(sec_hex))
>>> h160 = point.hash160()
>>> redeem_script = P2WPKHScriptPubKey(h160)
>>> h160_p2sh = hash160(redeem_script.raw_serialize())
>>> address = h160_to_p2sh_address(h160_p2sh, testnet=False)
>>> print(address)
3CobPD6RBnTZsFdka71XHQr4vHXDZMu2zm

#endcode
#exercise
#### Create a testnet p2sh-p2wpkh address with your private key.

---
>>> from ecc import PrivateKey
>>> from helper import encode_varstr, h160_to_p2sh_address, hash160, hash256, little_endian_to_int
>>> from script import P2WPKHScriptPubKey
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
>>> # encode to base58 using h160_to_p2sh_address, remember testnet=True
>>> address = h160_to_p2sh_address(p2sh_h160, testnet=True)  #/
>>> # print the address
>>> print(address)  #/
2N4MoSx2SoExv53GJFEdPuMqL8djPQPH2er

#endexercise
#unittest
script:ScriptTest:test_p2sh_address:
#endunittest
#unittest
ecc:S256Test:test_p2sh_p2wpkh_address:
#endunittest
#code
>>> # Example for signing a p2sh-p2wpkh input
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int, SIGHASH_ALL
>>> from script import Script
>>> from tx import Tx
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
>>> tx_in.witness = [sig, sec]
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

'''


from unittest import TestCase

from helper import (
    encode_varint,
    encode_varstr,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    read_varstr,
    SIGHASH_ALL,
)
from script import P2PKHScriptPubKey
from tx import Tx, TxIn, TxOut


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
        num_items = read_varint(s)
        tx_in.witness = []
        for _ in range(num_items):
            item = read_varstr(s)
            tx_in.witness.append(item)
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
        result += int_to_little_endian(len(tx_in.witness), 1)
        for item in tx_in.witness:
            result += encode_varstr(item)
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
    else:
        script_pubkey = tx_in.script_pubkey(self.testnet)
        h160 = script_pubkey.commands[1]
    s += P2PKHScriptPubKey(h160).serialize()
    s += int_to_little_endian(tx_in.value(testnet=self.testnet), 8)
    s += int_to_little_endian(tx_in.sequence, 4)
    s += self.hash_outputs()
    s += int_to_little_endian(self.locktime, 4)
    s += int_to_little_endian(SIGHASH_ALL, 4)
    return int.from_bytes(hash256(s), 'big')


class SessionTest(TestCase):

    def test_apply(self):
        Tx.parse_segwit = parse_segwit
        Tx.serialize_segwit = serialize_segwit
        Tx.sig_hash_bip143 = sig_hash_bip143
