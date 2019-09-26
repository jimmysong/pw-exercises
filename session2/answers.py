'''
#code
>>> import ecc, tx

#endcode
#unittest
tx:TxTest:test_verify_p2wsh:
#endunittest
#code
>>> # example for creating a p2wsh bech32 address
>>> from ecc import S256Point
>>> from helper import encode_bech32_checksum, encode_varstr, sha256
>>> from script import Script
>>> sec1_hex = '0375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c'
>>> sec2_hex = '03a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff'
>>> sec3_hex = '03c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f880'
>>> sec1 = bytes.fromhex(sec1_hex)
>>> sec2 = bytes.fromhex(sec2_hex)
>>> sec3 = bytes.fromhex(sec3_hex)
>>> witness_script = Script([0x52, sec1, sec2, sec3, 0x53, 0xae])  # 2-of-3 multisig
>>> s256 = sha256(witness_script.raw_serialize())
>>> s = Script([0, s256])
>>> raw = s.raw_serialize()
>>> bech32 = encode_bech32_checksum(raw, testnet=False)
>>> print(bech32)
bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej

#endcode
#exercise
#### Create a testnet 2-of-2 multisig p2wsh bech32 address using your private key from the Session 0 and this SEC public key:
`031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e`

Fill in the spreadsheet with the address.
---
>>> from ecc import PrivateKey
>>> from helper import encode_bech32_checksum, encode_varstr, hash256, little_endian_to_int, sha256
>>> from script import Script
>>> sec2 = bytes.fromhex('031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e')
>>> # use the same passphrase from session 0
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # create a private key using the secret
>>> private_key = PrivateKey(secret)  #/
>>> # get the public key using the .point property
>>> public_key = private_key.point  #/
>>> # get the compressed SEC format of the point
>>> sec1 = public_key.sec()  #/
>>> # create the WitnessScript 0x52 (OP_2), sec1, sec2, 0x52, 0xae (OP_CHECKMULTISIG)
>>> witness_script = Script([0x52, sec1, sec2, 0x52, 0xae])  #/
>>> # get the sha256 of the raw serialization of the script
>>> s256 = sha256(witness_script.raw_serialize())  #/
>>> # create another script of 0 (OP_0) and the hash
>>> s = Script([0, s256])  #/
>>> # get the raw serialization of the second script you just made
>>> raw = s.raw_serialize()  #/
>>> # encode to bech32 using encode_bech32_checksum, remember testnet=True
>>> bech32 = encode_bech32_checksum(raw, testnet=True)  #/
>>> # print the address
>>> print(bech32)  #/
tb1qk9g26ycdn47n2uhzl0nnj7ayxmzlveuhvzg7vtdkpcl3smkquvgqlp5t8w

#endexercise
#unittest
script:ScriptTest:test_p2wsh_address:
#endunittest
#code
>>> # Example for signing a p2wsh input
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int, SIGHASH_ALL
>>> from script import Script
>>> from tx import Tx
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> sec1 = private_key.point.sec()
>>> sec2 = bytes.fromhex('031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e')
>>> raw_tx_hex = '01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f0000000000160014092ab91b37b4182061d9c01199aaac029f89561f0000000000'
>>> input_index = 0
>>> stream = BytesIO(bytes.fromhex(raw_tx_hex))
>>> tx_obj = Tx.parse(stream, testnet=True)
>>> witness_script = Script([0x52, sec1, sec2, 0x52, 0xae])
>>> z = tx_obj.sig_hash_bip143(input_index, witness_script=witness_script)
>>> der = private_key.sign(z).der()
>>> sig = der + SIGHASH_ALL.to_bytes(1, 'big')
>>> print(sig.hex())
304402202770904ce7d2166fdc361ac5e2b3cf4acb02234b9c8d1ce540a3adc139a45b1802202bb03a8ce5cce7c70fe6eea32035e56970959feaea47bfe61a4cf78d7121b6ba01

#endcode
#unittest
tx:TxTest:test_sign_p2wsh_multisig:
#endunittest
#code
>>> # Example for creating a p2wsh multisig transaction
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from script import p2wpkh_script
>>> from tx import Tx, TxIn, TxOut
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> sec1 = private_key.point.sec()
>>> print(sec1.hex())
>>> sec2 = bytes.fromhex('031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e')
>>> witness_script = Script([0x52, sec1, sec2, 0x52, 0xae])
>>> sig2 = bytes.fromhex('304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa101')
>>> prev_tx_hex = 'a7f64bc20cd7d113d910a9a56fece31543677d98ee3180e6eabfbf9fccd360dc'
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> prev_index = 0
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> amount = tx_in.value(testnet=True) - fee
>>> target_address = 'tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au'
>>> _, _, h160 = decode_bech32(target_address)
>>> script_pubkey = p2wpkh_script(h160)
>>> tx_out = TxOut(amount, script_pubkey)
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
>>> sig1 = tx_obj.get_sig_p2wsh_multisig(0, private_key, witness_script)
>>> tx_obj.finalize_p2wsh_multisig_input(0, [sig1, sig2], witness_script)
True
>>> print(tx_obj.serialize().hex())
01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750400473044022041a5f6066f066bb35d2e426bec0fa673fe9737461153eea66e23ab39ffc4f73602203e351dee8e0e3dd3fb5a86adca7c5a0eaee48e4d655c3a9d4655d235e6ad5a630147304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa10147522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e52ae00000000

#endcode
#exercise

#### Create a p2wpkh spending transaction

You have been provided with an unsigned transaction, witness script and 1 of the 2 required signatures. Sign and broadcast the transaction!

---
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from network import SimpleNode
>>> from script import Script
>>> from tx import Tx, TxIn, TxOut
>>> hex_tx = '01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750000000000'
>>> hex_sig2 = '304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa101'
>>> hex_witness_script = '47522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e52ae'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> private_key = PrivateKey(little_endian_to_int(hash256(passphrase)))
>>> # turn the hex raw transaction into a stream
>>> stream = BytesIO(bytes.fromhex(hex_tx))  #/
>>> # parse the transaction, testnet=True
>>> tx_obj = Tx.parse(stream, testnet=True)  #/
>>> # turn the hex witness script into a stream
>>> stream = BytesIO(bytes.fromhex(hex_witness_script))  #/
>>> # parse the witness script using Script.parse
>>> witness_script = Script.parse(stream)  #/
>>> # convert the signature to bytes
>>> sig2 = bytes.fromhex(hex_sig2)  #/
>>> # get the other signature using get_sig_p2wsh_multisig for input 0
>>> sig1 = tx_obj.get_sig_p2wsh_multisig(0, private_key, witness_script=witness_script)  #/
>>> # finalize the transaction with the two signatures
>>> tx_obj.finalize_p2wsh_multisig_input(0, [sig1, sig2], witness_script=witness_script)  #/
True
>>> # print the hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750400473044022041a5f6066f066bb35d2e426bec0fa673fe9737461153eea66e23ab39ffc4f73602203e351dee8e0e3dd3fb5a86adca7c5a0eaee48e4d655c3a9d4655d235e6ad5a630147304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa10147522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e52ae00000000

#endexercise
#unittest
tx:TxTest:test_verify_p2sh_p2wsh:
#endunittest
#code
>>> # Example of generating a p2sh-p2wsh address
>>> from ecc import S256Point
>>> from helper import encode_base58_checksum, hash160, h160_to_p2sh_address
>>> sec_hex = '02c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d'
>>> point = S256Point.parse(bytes.fromhex(sec_hex))
>>> h160 = point.hash160()
>>> redeem_script = bytes([0]) + encode_varstr(h160)
>>> h160_p2sh = hash160(redeem_script)
>>> address = h160_to_p2sh_address(h160_p2sh, testnet=False)
>>> print(address)
3CobPD6RBnTZsFdka71XHQr4vHXDZMu2zm

#endcode
#exercise
#### Create a testnet p2sh-p2wpkh address with your private key.

---
>>> from ecc import PrivateKey
>>> from helper import encode_varstr, h160_to_p2sh_address, hash160, hash256, little_endian_to_int
>>> # use the same passphrase from session 0
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # create a private key using the secret
>>> private_key = PrivateKey(secret)  #/
>>> # get the public key using the .point property
>>> public_key = private_key.point  #/
>>> # get the hash160 of the point
>>> h160 = public_key.hash160()  #/
>>> # the RedeemScript starts with the segwit version (0 or b'\x00)
>>> redeem_script = bytes([0])  #/
>>> # next, add the hash160 to the RedeemScript using encode_varstr
>>> redeem_script += encode_varstr(h160)  #/
>>> # perform a hash160 to get the hash160 of the redeem script
>>> h160_p2sh = hash160(redeem_script)  #/
>>> # encode to base58 using h160_to_p2sh_address, remember testnet=True
>>> address = h160_to_p2sh_address(h160_p2sh, testnet=True)  #/
>>> # print the address
>>> print(address)  #/
2N4MoSx2SoExv53GJFEdPuMqL8djPQPH2er

#endexercise
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
>>> from script import p2wpkh_script
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
>>> script_pubkey = p2wpkh_script(h160)
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
>>> from script import p2wpkh_script, p2sh_script
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
>>> # create the target script pubkey using p2wpkh_script
>>> target_script_pubkey = p2wpkh_script(target_h160)  #/
>>> # add the target transaction output
>>> tx_outs.append(TxOut(target_amount, target_script_pubkey))
>>> # calculate the change amount, remember you were sent 5000000 sats
>>> change_amount = 5000000 - target_amount - fee  #/
>>> # get the p2sh-p2wpkh address for using your private key
>>> p2sh_address = private_key.point.p2sh_p2wpkh_address()  #/
>>> # get the hash160 by decoding the p2sh-p2wpkh address
>>> change_h160 = decode_base58(p2sh_address)
>>> # create the change script pubkey using p2sh_script
>>> change_script_pubkey = p2sh_script(change_h160)  #/
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
from script import p2pkh_script
from tx import Tx, TxIn, TxOut



class SessionTest(TestCase):
    pass
