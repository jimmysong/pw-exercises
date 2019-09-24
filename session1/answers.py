'''
#code
>>> import ecc, tx

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
>>> raw = b'\x00'
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
>>> raw = b'\x00'  #/
>>> # next, add the hash160 using encode_varstr
>>> raw += encode_varstr(h160)  #/
>>> # encode to bech32 using encode_bech32_checksum, remember testnet=True
>>> bech32 = encode_bech32_checksum(raw, testnet=True)  #/
>>> # print the address
>>> print(bech32)  #/
tb1qgqd0pdtu0f9hfyx9pzj86p686q70dtpwkmp0yw

#endexercise
#unittest
ecc:S256Test:test_address:
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
    s += p2pkh_script(tx_in.script_pubkey(self.testnet).commands[1]).serialize()
    s += int_to_little_endian(tx_in.value(), 8)
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
