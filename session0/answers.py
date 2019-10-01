
'''
#code
>>> import ecc, helper, tx
>>> from tx import TxFetcher
>>> TxFetcher.load_cache('tx.cache')

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
It's annoying to have to calculate z every time we want to sign or verify a message. Write the `sign_message` method in `PrivateKey` and the `verify_message` method in `S256Point` to make signing/verifying messages easy.
#endunittest
#exercise
#### Address Refresher

Get your testnet address from your private key used above.
---
>>> # get the public key for your private key (the private_key variable should still be in scope)
>>> public_key = private_key.point  #/
>>> # print the address using the address method. remember to pass in testnet=True!
>>> print(public_key.address(testnet=True))  #/
mmMupB3E1xNfRZktg6N9ehuAZWCkrCSXSp

#endexercise
#exercise
#### Transaction Refresher

Send yourself some testnet coins to the address from the previous exercise [using this site](https://faucet.programmingbitcoin.com).
Then create a transaction to send all the coins to `mqYz6JpuKukHzPg94y4XNDdPCEJrNkLQcv` BUT DO NOT BROADCAST IT YET!
This is a one input, one output transaction.
---
>>> from helper import decode_base58
>>> from script import P2PKHScriptPubKey
>>> from tx import Tx, TxIn, TxOut
>>> # this should be the transaction ID and index from the transaction from the faucet
>>> prev_tx_hex = 'aec4b5bfa8952a80a93e9afd437f4783e51d363303c021f68c7a614ca8a153e4'  #/prev_tx_hex = '<fill this in>'
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
>>> # convert the h160 to a p2pkh script using P2PKHScriptPubKey
>>> script_pubkey = P2PKHScriptPubKey(h160)  #/
>>> # create the transaction output
>>> tx_out = TxOut(output_amount, script_pubkey)  #/
>>> # create the transaction with version=1, locktime=0, testnet=True
>>> tx_obj = Tx(1, [tx_in], [tx_out], 0, testnet=True)  #/
>>> # sign the transaction's only input using sign_p2pkh
>>> # the private key from the previous exercise should be in scope
>>> tx_obj.sign_p2pkh(0, private_key)  #/
True
>>> # serialize and hex to see what it looks like
>>> print(tx_obj.serialize().hex())  #/
0100000001e453a1a84c617a8cf621c00333361de583477f43fd9a3ea9802a95a8bfb5c4ae010000006b483045022100919c5f390ac25e7aa66c250bb55f37a4ccf565a9681343cf822220c06879b4e9022027d4d2f691e31749280d30bf840160b6b8b682fff4481e84094a732b791917d2012102c3700ce19990bccbfa1e072d287049d7c0e07ed15c9aeac84bbc2c38ea667a5dffffffff01f7f03900000000001976a9146e13971913b9aa89659a9f53d327baa8826f2d7588ac00000000

#endexercise
#unittest
tx:TxTest:test_sign_input:
It's annoying to have to already know what the previous output's script type was to sign it as the caller. Create a method to sign any input, though for now, that should only be p2pkh.
#endunittest
'''


from unittest import TestCase

import helper

from ecc import PrivateKey, S256Point
from helper import encode_varint, hash256, read_varint
from script import P2PKHScriptPubKey
from tx import Tx


def read_varstr(s):
    item_length = read_varint(s)
    return s.read(item_length)


def encode_varstr(b):
    result = encode_varint(len(b))
    result += b
    return result


def sign_message(self, message):
    h256 = hash256(message)
    z = int.from_bytes(h256, 'big')
    return self.sign(z)


def verify_message(self, message, sig):
    h256 = hash256(message)
    z = int.from_bytes(h256, 'big')
    return self.verify(z, sig)


def sign_input(self, input_index, private_key):
    tx_in = self.tx_ins[input_index]
    script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
    if isinstance(script_pubkey, P2PKHScriptPubKey):
        return self.sign_p2pkh(input_index, private_key)
    else:
        raise RuntimeError('Unknown ScriptPubKey')


class SessionTest(TestCase):

    def test_apply(self):
        helper.read_varstr = read_varstr
        helper.encode_varstr = encode_varstr
        PrivateKey.sign_message = sign_message
        S256Point.verify_message = verify_message
        Tx.sign_input = sign_input


if __name__ == "__main__":
    import doctest
    doctest.testmod()
