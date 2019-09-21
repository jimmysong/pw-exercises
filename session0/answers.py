'''
#code
>>> import ecc, helper

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
This is a refresher on how some of the byte encoding and reading works. In particular, this exercise is to give you a refresher on how streams work.

Open [helper.py](/edit/session0/helper.py) and implement the `read_varstr` and `encode_varstr` functions. Once you're done editing, run the cell below.
#endunittest
#exercise
#### ECDSA Refresher

Sign the message `b'I completed the Programming Blockchain Seminar and/or the Programming Bitcoin book'` with a private key of your choosing. We'll use this key for at least a part of this class, so please keep it handy and back it up! 
---
>>> from ecc import PrivateKey
>>> from helper import hash256, little_endian_to_int
>>> # pick a secret passphrase. Something like your email address and your name should be fine.
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<some secret passphrase>'
>>> # this is the message we'll be signing
>>> message = b'I completed the Programming Blockchain Seminar and/or the Programming Bitcoin book'
>>> # we're converting the passphrase into a secret number for use in the private key
>>> secret = little_endian_to_int(hash256(passphrase))
>>> # create the private key object
>>> private_key = PrivateKey(secret)  #/
>>> # create the z by converting the hash256 of the message to a big endian integer using int.from_bytes(x, 'big')
>>> z = int.from_bytes(hash256(message), 'big')  #/
>>> # sign the message with the private key
>>> signature = private_key.sign(z)  #/
>>> # print the hex of the der version of the signature
>>> print(signature.der().hex())  #/
30450221009daf110ed47cf2e5b0b59e766af5476a35dcaadfbbd03250857cd7c2d2dc661302206cc4b3a5347e9215915f9e31084d4f49e07c34717a79d01aec259fd65381e74e
>>> # verify the signature using the public key (private_key.point)
>>> print(private_key.point.verify(z, signature))  #/
True
#endexercise
#unittest
ecc:PrivateKeyTest:test_sign_message:
It's annoying to have to calculate z every time we want to sign or verify a message. Write the `sign_message` method in `PrivateKey` and the 'verify_message` method in `S256Point' to make signing/verifying messages easy.
#endunittest
#exercise
#### Address Refresher

Get your testnet address from your private key used above.
---
>>> # get the public key for your private key (the private_key variable should still be in scope)
>>> public_key = private_key.point  #/
>>> # print the address using the address method. remember to pass in testnet=True!
>>> print(public_key.address(testnet=True))  #/

#endexercise
#exercise
#### Transaction Refresher

Send yourself some testnet coins to the address from the previous exercise [using this site](https://faucet.programmingbitcoin.com).
Then create a transaction to send all the coins to `mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv` and broadcast it via the testnet network.
This is a one input, one output transaction.
---
>>> from helper import decode_base58
>>> from network import SimpleNode
>>> from script import p2pkh_script
>>> from time import sleep
>>> from tx import Tx, TxIn, TxOut
>>> prev_tx_hex = 'ec7ae33dee6fe3263299f3000045565df305976b9f4bb279917980c0a3c27598'  #/prev_tx_hex = '<fill this in>'
>>> prev_index = 1  #/prev_index = -1  # change this
>>> prev_tx = bytes.fromhex(prev_tx_hex)
>>> target_address = 'mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv'
>>> fee = 5000
>>> # create the transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the output amount
>>> output_amount = tx_in.value(testnet=True) - fee  #/
>>> # calculate the hash160 using decode_base58 on the target_address
>>> h160 = decode_base58(target_address)  #/
>>> # convert the h160 to a p2pkh script using p2pkh_script
>>> script_pubkey = p2pkh_script(h160)  #/
>>> # create the transaction output
>>> tx_out = TxOut(output_amount, script_pubkey)  #/
>>> # create the transaction with version=1, locktime=0, testnet=True
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)  #/
>>> # sign the transaction's only input
>>> # the private key from the previous exercise should be in scope
>>> tx_obj.sign_input(0, private_key)  #/
>>> # serialize and hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
01000000019875c2a3c080799179b24b9f6b9705f35d56450000f3993226e36fee3de37aec010000006b483045022100d7d9b02f29d986c2a63d941e098b9133802e5d267481633bfff241c392e8349902205b6628b1450f65e4da872458a59b69e220481815887117bf401691b93800ac26012102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5dffffffff01b82e0f00000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000
>>> # connect to tbtc.programmingblockchain.com in testnet mode using SimpleNode
>>> node = SimpleNode('testnet.programmingbitcoin.com', testnet=True)  #/
>>> # complete the handshake
>>> node.handshake()  #/
>>> # send this signed transaction on the network
>>> node.send(tx_obj)  #/
>>> # wait a sec so this message goes through to the other node sleep(1)
>>> sleep(1)  #/
>>> # now check to see if the tx has been accepted using SimpleNode.is_tx_accepted()
>>> if node.is_tx_accepted(tx_obj):  #/
...     print('success!')  #/
...     print(tx_obj.id())  #/
success!
fa474e98c0e9a776f6f0a06ad0d4f1150b35bb51875592c0927056cc7bd99cc9

#endexercise
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
