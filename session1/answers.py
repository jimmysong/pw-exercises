'''
#unittest
tx:TxTest:test_parse_segwit:
#endunittest
#unittest
tx:TxTest:test_serialize_segwit:
#endunittest
#unittest
tx:TxTest:test_sig_hash_bip143:
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
