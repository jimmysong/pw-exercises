'''
#code
>>> import ecc, script, tx

#endcode
#unittest
tx:TxTest:test_verify_p2wsh:
#endunittest
#code
>>> # example for creating a p2wsh bech32 address
>>> from ecc import S256Point
>>> from helper import encode_bech32_checksum, encode_varstr, sha256
>>> from script import Script, WitnessScript
>>> sec1_hex = '0375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c'
>>> sec2_hex = '03a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff'
>>> sec3_hex = '03c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f880'
>>> sec1 = bytes.fromhex(sec1_hex)
>>> sec2 = bytes.fromhex(sec2_hex)
>>> sec3 = bytes.fromhex(sec3_hex)
>>> witness_script = WitnessScript([0x52, sec1, sec2, sec3, 0x53, 0xae])  # 2-of-3 multisig
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
>>> from script import Script, WitnessScript
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
>>> witness_script = WitnessScript([0x52, sec1, sec2, 0x52, 0xae])  #/
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
script:WitnessScriptTest:test_address:
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
>>> witness_script = WitnessScript([0x52, sec1, sec2, 0x52, 0xae])
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
>>> # Example for signing a p2wsh multisig transaction
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from script import P2WPKHScriptPubKey
>>> from tx import Tx, TxIn, TxOut
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> sec1 = private_key.point.sec()
>>> sec2 = bytes.fromhex('031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e')
>>> witness_script = WitnessScript([0x52, sec1, sec2, 0x52, 0xae])
>>> sig2 = bytes.fromhex('304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa101')
>>> prev_tx_hex = 'a7f64bc20cd7d113d910a9a56fece31543677d98ee3180e6eabfbf9fccd360dc'
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> prev_index = 0
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> amount = tx_in.value(testnet=True) - fee
>>> target_address = 'tb1qdcfewxgnhx4gjev6nafaxfa64zpx7tt470r3au'
>>> _, _, h160 = decode_bech32(target_address)
>>> script_pubkey = P2WPKHScriptPubKey(h160)
>>> tx_out = TxOut(amount, script_pubkey)
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
>>> sig1 = tx_obj.get_sig_segwit(0, private_key, witness_script=witness_script)
>>> tx_in.finalize_p2wsh_multisig([sig1, sig2], witness_script)
>>> print(tx_obj.serialize().hex())
01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750400473044022041a5f6066f066bb35d2e426bec0fa673fe9737461153eea66e23ab39ffc4f73602203e351dee8e0e3dd3fb5a86adca7c5a0eaee48e4d655c3a9d4655d235e6ad5a630147304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa10147522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e52ae00000000

#endcode
#exercise

#### Create a p2wsh spending transaction

You have been provided with an unsigned transaction, witness script and 1 of the 2 required signatures. Sign and broadcast the transaction!

---
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from network import SimpleNode
>>> from script import Script, WitnessScript
>>> from tx import Tx, TxIn, TxOut
>>> hex_tx = '01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750000000000'  #/hex_tx = '<fill this in>'
>>> hex_sig2 = '304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa101'  #/hex_sig2 = '<fill this in>'
>>> hex_witness_script = '47522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e52ae'  #/hex_witness_script = '<fill this in>'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> private_key = PrivateKey(little_endian_to_int(hash256(passphrase)))
>>> # turn the hex raw transaction into a stream
>>> stream = BytesIO(bytes.fromhex(hex_tx))  #/
>>> # parse the transaction, testnet=True
>>> tx_obj = Tx.parse(stream, testnet=True)  #/
>>> # turn the hex witness script into a stream
>>> stream = BytesIO(bytes.fromhex(hex_witness_script))  #/
>>> # parse the witness script using Script.parse
>>> witness_script = WitnessScript.parse(stream)  #/
>>> # convert the signature to bytes
>>> sig2 = bytes.fromhex(hex_sig2)  #/
>>> # get the other signature using get_sig_segwit for input 0
>>> sig1 = tx_obj.get_sig_segwit(0, private_key, witness_script=witness_script)  #/
>>> # finalize the first input with the two signatures
>>> tx_obj.tx_ins[0].finalize_p2wsh_multisig([sig1, sig2], witness_script=witness_script)  #/
>>> # print the hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
01000000000101dc60d3cc9fbfbfeae68031ee987d674315e3ec6fa5a910d913d1d70cc24bf6a70000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750400473044022041a5f6066f066bb35d2e426bec0fa673fe9737461153eea66e23ab39ffc4f73602203e351dee8e0e3dd3fb5a86adca7c5a0eaee48e4d655c3a9d4655d235e6ad5a630147304402206f68a4c8731b1981fde3ae2f8ac3e21dbb42903853a3cecf18c30c31d36b510102207e5eba87f5d9134307d0f0cfb3eb065b18bf8a35df9a8b10538586328d1c7aa10147522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e52ae00000000

#endexercise
#code
>>> # Example of generating a p2sh-p2wsh address
>>> from ecc import S256Point
>>> from helper import encode_base58_checksum, hash160, sha256
>>> from script import Script, WitnessScript, P2WSHScriptPubKey
>>> sec1_hex = '026ccfb8061f235cc110697c0bfb3afb99d82c886672f6b9b5393b25a434c0cbf3'
>>> sec2_hex = '03befa190c0c22e2f53720b1be9476dcf11917da4665c44c9c71c3a2d28a933c35'
>>> sec3_hex = '02be46dc245f58085743b1cc37c82f0d63a960efa43b5336534275fc469b49f4ac'
>>> sec1 = bytes.fromhex(sec1_hex)
>>> sec2 = bytes.fromhex(sec2_hex)
>>> sec3 = bytes.fromhex(sec3_hex)
>>> witness_script = WitnessScript([0x52, sec1, sec2, sec3, 0x53, 0xae])  # 2-of-3 multisig
>>> s256 = sha256(witness_script.raw_serialize())
>>> redeem_script = P2WSHScriptPubKey(s256)
>>> print(redeem_script.p2sh_address(testnet=True))
2MvVx9ccWqyYVNa5Xz9pfCEVk99zVBZh9ms

#endcode
#exercise
#### Create a testnet 2-of-3 multisig p2sh-p2wsh address with your private key and the two sec pubkeys provided.

---
>>> from ecc import PrivateKey
>>> from helper import encode_varstr, hash160, hash256, sha256, little_endian_to_int
>>> from script import P2WSHScriptPubKey, Script
>>> sec2 = bytes.fromhex('031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e')
>>> sec3 = bytes.fromhex('02618b836fc32578538bb8440f5e89d916844dd828981a9bc33f9a736638b538d2')
>>> # use the same passphrase from session 0
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # create a private key using the secret
>>> private_key = PrivateKey(secret)  #/
>>> # get the sec using the .point property
>>> sec1 = private_key.point.sec()  #/
>>> # create a WitnessScript that's 2 of 3 multisig
>>> witness_script = WitnessScript([0x52, sec1, sec2, sec3, 0x53, 0xae])  #/
>>> # get the sha256 of the raw serialization of the witness script
>>> s256 = sha256(witness_script.raw_serialize())  #/
>>> # make the RedeemScript using the P2WSHScriptPubKey function on the sha256
>>> redeem_script = P2WSHScriptPubKey(s256)  #/
>>> # print the RedeemScript's p2sh address
>>> print(redeem_script.p2sh_address(testnet=True))  #/
2N6x1Y58uwZ7oYAZSeYveaYHGKHvotUUfyZ

#endexercise
#unittest
script:WitnessScriptTest:test_p2sh_address:
#endunittest
#code
>>> # Example for signing a p2sh-p2wsh input
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int, SIGHASH_ALL
>>> from script import Script, WitnessScript
>>> from tx import Tx
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> hex_tx = '01000000000101ec13653fae5706168e92d9a3e4d98044d4af001a3081a70e57865caf94e0b7ee0000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750000000000'
>>> hex_witness_script = '69522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e2102618b836fc32578538bb8440f5e89d916844dd828981a9bc33f9a736638b538d253ae'
>>> stream = BytesIO(bytes.fromhex(hex_tx))
>>> tx_obj = Tx.parse(stream, testnet=True)
>>> stream = BytesIO(bytes.fromhex(hex_witness_script))
>>> witness_script = WitnessScript.parse(stream)
>>> z = tx_obj.sig_hash_bip143(input_index, witness_script=witness_script)
>>> der = private_key.sign(z).der()
>>> sig = der + SIGHASH_ALL.to_bytes(1, 'big')
>>> print(sig.hex())
30440220603857be62aec5b6e16a13659fd7ca36f822b92999a7303f7ab3be6481227acf022020a56a52cb2088def4c12d2e2fa7055f4582b0a5aba7db4c169777456378db0501

#endcode
#unittest
tx:TxTest:test_sign_p2sh_p2wsh_multisig:
#endunittest
#code
>>> # Example for signing a p2sh-p2wsh multisig transaction
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from script import Script, WitnessScript
>>> from tx import Tx, TxIn, TxOut
>>> private_key = PrivateKey(little_endian_to_int(hash256(b'jimmy@programmingblockchain.com Jimmy Song')))
>>> hex_tx = '01000000000101ec13653fae5706168e92d9a3e4d98044d4af001a3081a70e57865caf94e0b7ee0000000000ffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750000000000'
>>> hex_witness_script = '69522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e2102618b836fc32578538bb8440f5e89d916844dd828981a9bc33f9a736638b538d253ae'
>>> hex_sig2 = '3045022100e9fa8587958b540ac71f128629e3019f07b14b0e5eb248afb3d4f92ddfee9f6002201bda6dc9297471419a00d86899f753d6c015e42d51df9aa1d8b5dc53f595d9e401'
>>> stream = BytesIO(bytes.fromhex(hex_tx))
>>> tx_obj = Tx.parse(stream, testnet=True)
>>> stream = BytesIO(bytes.fromhex(hex_witness_script))
>>> witness_script = WitnessScript.parse(stream)
>>> sig2 = bytes.fromhex(hex_sig2)
>>> sig1 = tx_obj.get_sig_segwit(0, private_key, witness_script=witness_script)
>>> tx_obj.tx_ins[0].finalize_p2sh_p2wsh_multisig([sig1, sig2], witness_script)
>>> print(tx_obj.serialize().hex())
01000000000101ec13653fae5706168e92d9a3e4d98044d4af001a3081a70e57865caf94e0b7ee0000000023220020df9f2354c7040acd8ab725dc356bfafcae5b291e4d3f30685aede1d2a5d35dacffffffff014c400f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7504004730440220603857be62aec5b6e16a13659fd7ca36f822b92999a7303f7ab3be6481227acf022020a56a52cb2088def4c12d2e2fa7055f4582b0a5aba7db4c169777456378db0501483045022100e9fa8587958b540ac71f128629e3019f07b14b0e5eb248afb3d4f92ddfee9f6002201bda6dc9297471419a00d86899f753d6c015e42d51df9aa1d8b5dc53f595d9e40169522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e2102618b836fc32578538bb8440f5e89d916844dd828981a9bc33f9a736638b538d253ae00000000

#endcode
#exercise

#### Create a p2sh-p2wsh spending transaction

You have been provided with an unsigned transaction, witness script and 1 of the 2 required signatures. Sign and broadcast the transaction!
02c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d,2N6x1Y58uwZ7oYAZSeYveaYHGKHvotUUfyZ,010000000001010b73fcaf0ca900bcc86017773be47d6533a3da445e962b0c708d012fb025943d0000000000ffffffff014c494c00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750000000000,3045022100e220b8ebb30bdd78135d4f397881e7754453c3470e6eaa016c1db66ed2106ecf022035d496ca50a6bd5a494e5250c1ed1797faa7afa496aa0599f759d596ed74ef4601
---
>>> from io import BytesIO
>>> from ecc import PrivateKey
>>> from helper import decode_bech32, hash256, little_endian_to_int
>>> from network import SimpleNode
>>> from script import Script, WitnessScript
>>> from tx import Tx, TxIn, TxOut
>>> hex_tx = '010000000001010b73fcaf0ca900bcc86017773be47d6533a3da445e962b0c708d012fb025943d0000000000ffffffff014c494c00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750000000000'  #/hex_tx = '<fill this in>'
>>> hex_witness_script = '69522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e2102618b836fc32578538bb8440f5e89d916844dd828981a9bc33f9a736638b538d253ae'  #/hex_witness_script = '<fill this in>'
>>> hex_sig2 = '3045022100e220b8ebb30bdd78135d4f397881e7754453c3470e6eaa016c1db66ed2106ecf022035d496ca50a6bd5a494e5250c1ed1797faa7afa496aa0599f759d596ed74ef4601'  #/hex_sig2 = '<fill this in>'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> private_key = PrivateKey(little_endian_to_int(hash256(passphrase)))
>>> # turn the hex raw transaction into a stream
>>> stream = BytesIO(bytes.fromhex(hex_tx))  #/
>>> # parse the transaction, testnet=True
>>> tx_obj = Tx.parse(stream, testnet=True)  #/
>>> # turn the hex witness script into a stream
>>> stream = BytesIO(bytes.fromhex(hex_witness_script))  #/
>>> # parse the witness script using Script.parse
>>> witness_script = WitnessScript.parse(stream)  #/
>>> # convert the signature to bytes
>>> sig2 = bytes.fromhex(hex_sig2)  #/
>>> # get the other signature using get_sig_segwit for input 0
>>> sig1 = tx_obj.get_sig_segwit(0, private_key, witness_script=witness_script)  #/
>>> # finalize the first input with the two signatures
>>> tx_obj.tx_ins[0].finalize_p2sh_p2wsh_multisig([sig1, sig2], witness_script=witness_script)  #/
>>> # print the hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
010000000001010b73fcaf0ca900bcc86017773be47d6533a3da445e962b0c708d012fb025943d0000000023220020df9f2354c7040acd8ab725dc356bfafcae5b291e4d3f30685aede1d2a5d35dacffffffff014c494c00000000001600146e13971913b9aa89659a9f53d327baa8826f2d750400483045022100d634e45c226811e12918413c914393d4f631812111030cb91344920e4ced03e50220335f404884d2b33fa0fa4149e77ec47b41a0c3ec5b4c91fcf2a70a2e92ee83a701483045022100e220b8ebb30bdd78135d4f397881e7754453c3470e6eaa016c1db66ed2106ecf022035d496ca50a6bd5a494e5250c1ed1797faa7afa496aa0599f759d596ed74ef460169522102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5d21031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e2102618b836fc32578538bb8440f5e89d916844dd828981a9bc33f9a736638b538d253ae00000000

#endexercise
'''


from unittest import TestCase

from helper import (
    big_endian_to_int,
    encode_bech32_checksum,
    hash256,
    int_to_little_endian,
    SIGHASH_ALL,
)
from script import (
    P2PKHScriptPubKey,
    RedeemScript,
    Script,
    WitnessScript,
)
from tx import Tx, TxIn
from witness import Witness


def sig_hash_bip143(self, input_index, redeem_script=None, witness_script=None):
    tx_in = self.tx_ins[input_index]
    s = int_to_little_endian(self.version, 4)
    s += self.hash_prevouts() + self.hash_sequence()
    s += tx_in.prev_tx[::-1]
    s += int_to_little_endian(tx_in.prev_index, 4)
    if witness_script:
        script_code = witness_script
    elif redeem_script:
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
    return big_endian_to_int(hash256(s))


def verify_input(self, input_index):
    tx_in = self.tx_ins[input_index]
    script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
    if script_pubkey.is_p2sh():
        raw_redeem_script = tx_in.script_sig.commands[-1]
        redeem_script = RedeemScript.convert(raw_redeem_script)
    else:
        redeem_script = None
    if script_pubkey.is_p2wsh() or (redeem_script and redeem_script.is_p2wsh()):
        raw_witness_script = tx_in.witness.items[-1]
        witness_script = WitnessScript.convert(raw_witness_script)
    else:
        witness_script = None
    if script_pubkey.is_p2wpkh() or (redeem_script and redeem_script.is_p2wpkh()) \
       or script_pubkey.is_p2wsh() or (redeem_script and redeem_script.is_p2wsh()):
        z = self.sig_hash_bip143(input_index, redeem_script, witness_script)
    else:
        z = self.sig_hash(input_index, redeem_script)
    combined_script = tx_in.script_sig + tx_in.script_pubkey(self.testnet)
    return combined_script.evaluate(z, tx_in.witness)


def finalize_p2sh_multisig(self, signatures, redeem_script):
    script_sig = Script([0, *signatures, redeem_script.raw_serialize()])
    self.script_sig = script_sig


def finalize_p2wsh_multisig(self, signatures, witness_script):
    items = [b'\x00', *signatures, witness_script.raw_serialize()]
    self.witness = Witness(items)


def finalize_p2sh_p2wsh_multisig(self, signatures, witness_script):
    items = [b'\x00', *signatures, witness_script.raw_serialize()]
    self.witness = Witness(items)
    redeem_script = witness_script.script_pubkey()
    self.script_sig = Script([redeem_script.raw_serialize()])


def address(self, testnet=False):
    witness_program = self.script_pubkey().raw_serialize()
    return encode_bech32_checksum(witness_program, testnet)


def p2sh_address(self, testnet=False):
    redeem_script = self.script_pubkey().redeem_script()
    return redeem_script.address(testnet)


class SessionTest(TestCase):

    def test_apply(self):
        TxIn.finalize_p2sh_multisig = finalize_p2sh_multisig
        TxIn.finalize_p2wsh_multisig = finalize_p2wsh_multisig
        TxIn.finalize_p2sh_p2wsh_multisig = finalize_p2sh_p2wsh_multisig
        Tx.sig_hash_bip143 = sig_hash_bip143
        Tx.verify_input = verify_input
        WitnessScript.address = address
        WitnessScript.p2sh_address = p2sh_address
