'''
#code
>>> import helper

#endcode
#markdown
### This is a Jupyter Notebook
You can write Python code and it will execute. You can write the typical 'hello world' program like this:

```python
print('hello world')
```

You can execute by pressing shift-enter. Try it! You can also click the Run button in the toolbar.
#endmarkdown
#code
>>> print('hello world')
hello world

#endcode
#markdown
### Imports

You already have unit tests that are written for you.
Your task is to make them pass.
We can import various modules to make our experience using Jupyter more pleasant.
This way, making everything work will be a lot easier.
#endmarkdown
#code
>>> # this is how you import an entire module
>>> import helper
>>> 
>>> # this is how you import a particular function, class or constant
>>> from helper import little_endian_to_int
>>> 
>>> # used in the next exercise
>>> some_long_variable_name = 'something'

#endcode
#exercise
#### Jupyter Tips

The two most useful commands are tab and shift-tab

Tab lets you tab-complete. Try pressing tab after the `some` below. This will complete to the variable name that's there from the last cell.

Shift-Tab gives you a function/method signature. Try pressing shift-tab after the `little_endian_to_int` below. That's also there from the last cell.
---
>>> some_long_variable_name  #/some  # press *tab* here
'something'
>>> little_endian_to_int(b'\\x00')  #/little_endian_to_int()  # press shift-tab here
0

#endexercise
#unittest
helper:HelperTest:test_varstr:
Open [helper.py](/edit/session0/helper.py) and implement the `read_varstr` and `encode_varstr` functions. Once you're done editing, run the cell below.
#endunittest
'''


from unittest import TestCase

from bloomfilter import (
    BloomFilter,
    BIP37_CONSTANT,
)
from ecc import PrivateKey
from helper import (
    bit_field_to_bytes,
    bytes_to_bit_field,
    decode_base58,
    hash160,
    hash256,
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    murmur3,
)
from merkleblock import (
    MerkleBlock,
    MerkleTree,
)
from network import (
    GenericMessage,
    GetDataMessage,
    GetHeadersMessage,
    HeadersMessage,
    SimpleNode,
    FILTERED_BLOCK_DATA_TYPE,
)
from script import p2pkh_script
from tx import (
    Tx,
    TxIn,
    TxOut,
)


def add(self, item):
    for i in range(self.function_count):
        seed = i * BIP37_CONSTANT + self.tweak
        h = murmur3(item, seed=seed)
        bit = h % (self.size * 8)
        self.bit_field[bit] = 1


def filterload(self, flag=1):
    payload = encode_varint(self.size)
    payload += self.filter_bytes()
    payload += int_to_little_endian(self.function_count, 4)
    payload += int_to_little_endian(self.tweak, 4)
    payload += int_to_little_endian(flag, 1)
    return GenericMessage(b'filterload', payload)


def serialize(self):
    result = encode_varint(len(self.data))
    for data_type, identifier in self.data:
        result += int_to_little_endian(data_type, 4)
        result += identifier[::-1]
    return result


def get_filtered_txs(self, block_hashes):
    getdata = GetDataMessage()
    for block_hash in block_hashes:
        getdata.add_data(FILTERED_BLOCK_DATA_TYPE, block_hash)
    self.send(getdata)
    results = []
    for block_hash in block_hashes:
        mb = self.wait_for(MerkleBlock)
        if mb.hash() != block_hash:
            raise RuntimeError('Wrong block sent')
        if not mb.is_valid():
            raise RuntimeError('Merkle Proof is invalid')
        for tx_hash in mb.proved_txs():
            tx_obj = self.wait_for(Tx)
            if tx_obj.hash() != tx_hash:
                raise RuntimeError('Wrong tx sent {} vs {}'.format(tx_hash.hex(), tx_obj.id()))
            results.append(tx_obj)
    return results


class Session8Test(TestCase):

    def test_apply(self):
        BloomFilter.add = add
        BloomFilter.filterload = filterload
        GetDataMessage.serialize = serialize
        SimpleNode.get_filtered_txs = get_filtered_txs


if __name__ == "__main__":
    import doctest
    doctest.testmod()
