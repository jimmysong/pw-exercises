'''
#code
>>> import hd, tx

#endcode
#code
>>> # Example Master Key Generation
>>> from ecc import PrivateKey
>>> from helper import big_endian_to_int, hmac_sha512, raw_decode_base58
>>> from hd import HDPrivateKey
>>> seed = b'jimmy@programmingblockchain.com Jimmy Song'
>>> h = hmac_sha512(b'Bitcoin seed', seed)
>>> private_key = PrivateKey(secret=big_endian_to_int(h[:32]))
>>> chain_code = h[32:]
>>> master = HDPrivateKey(
...     private_key=private_key,
...     chain_code=chain_code,
...     testnet=True,
... )
>>> print(master.bech32_address())
tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg

#endcode
#unittest
hd:HDTest:test_from_seed:
#endunittest
#code
>>> # Example Unhardened Child Derivation
>>> from ecc import N
>>> from hd import HDPrivateKey
>>> from helper import big_endian_to_int, hmac_sha512, int_to_big_endian
>>> seed_phrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> master = HDPrivateKey.from_seed(seed_phrase, True)
>>> index = 0
>>> data = master.private_key.point.sec() + int_to_big_endian(index, 4)
>>> h = hmac_sha512(master.chain_code, data)
>>> secret = (big_endian_to_int(h[:32]) + master.private_key.secret) % N
>>> unhardened_child = HDPrivateKey(
...     private_key=PrivateKey(secret=secret),
...     chain_code=h[32:],
...     depth=master.depth + 1,
...     parent_fingerprint=master.fingerprint(),
...     child_number=index,
...     testnet=master.testnet,
... )
>>> print(unhardened_child.bech32_address())
tb1qu6mnnk54hxfhy4aj58v0w6e7q8hghtv8wcdl7g

#endcode
#code
>>> # Example Hardened Child Derivation
>>> from ecc import N
>>> from hd import HDPrivateKey
>>> from helper import big_endian_to_int, hmac_sha512, int_to_big_endian
>>> seed_phrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> master = HDPrivateKey.from_seed(seed_phrase, True)
>>> index = 0x80000002
>>> data = int_to_big_endian(master.private_key.secret, 33) + int_to_big_endian(index, 4)
>>> h = hmac_sha512(master.chain_code, data)
>>> secret = (big_endian_to_int(h[:32]) + master.private_key.secret) % N
>>> hardened_child = HDPrivateKey(
...     private_key=PrivateKey(secret=secret),
...     chain_code=h[32:],
...     depth=master.depth + 1,
...     parent_fingerprint=master.fingerprint(),
...     child_number=index,
...     testnet=master.testnet,
... )
>>> print(hardened_child.bech32_address())
tb1qscu8evdlqsucj7p84xwnrf63h4jsdr5yqga8zq

#endcode
#unittest
hd:HDTest:test_child:
#endunittest
#code
>>> # example of private key path traversal
>>> from hd import HDPrivateKey
>>> seed_phrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> master = HDPrivateKey.from_seed(seed_phrase, True)
>>> current = master
>>> path = "m/0/1'/2/3'"
>>> components = path.split('/')[1:]
>>> for child in components:
...     if child.endswith("'"):
...         index = int(child[:-1]) + 0x80000000
...     else:
...         index = int(child)
...     current = current.child(index)
>>> print(current.bech32_address())
tb1q423gz8cenqt6vfw987vlyxql0rh2jgh4sy0tue

#endcode
#unittest
hd:HDTest:test_traverse:
#endunittest
#code
>>> # Example to create an xpub
>>> from hd import HDPrivateKey
>>> from helper import encode_base58_checksum, int_to_byte, int_to_big_endian
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> hd_priv = HDPrivateKey.from_seed(passphrase)
>>> raw = bytes.fromhex('0488b21e')
>>> raw += int_to_byte(hd_priv.depth)
>>> raw += hd_priv.parent_fingerprint
>>> raw += int_to_big_endian(hd_priv.child_number, 4)
>>> raw += hd_priv.chain_code
>>> raw += hd_priv.pub.point.sec()
>>> print(encode_base58_checksum(raw))
xpub661MyMwAqRbcEpBhPYKfaLbRYynwb4fyL7N7xxB98h3sH5br3Tu4iNSe2S7yyP3AFXFoYRyZUWXJFw8o4sAaSTTQZLf8y3YJLRnJqSfnoWT

#endcode
#unittest
hd:HDTest:test_prv_pub:
#endunittest
#unittest
hd:HDTest:test_parse:
#endunittest
#exercise

#### Create an extended public key

Create a xpub on testnet (should start with tpub)

---
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # print the xpub
>>> print(hd_priv.xpub())  #/
tpubD6NzVbkrYhZ4WcNYqjJknFvnt6tbaTB2sjxRKWEHUbom2NGZ7gk9rp7UGUCmVszQ3RniA1VS1cMLx7dQTj1pKtuhcwQSeaCXvPNibUHNR3F

#endexercise
#code
>>> # Example of getting p2pkh/p2sh-p2wpkh/p2wpkh testnet addresses
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)
>>> # p2pkh
>>> p2pkh_path = "m/44'/1'/0'/0/0"
>>> print(hd_priv.traverse(p2pkh_path).address())
mpLAmKy2kMhTFSHRKcJzhdRTMjWYRp5rdt
>>> # p2sh-p2wpkh
>>> p2sh_p2wpkh_path = "m/49'/1'/0'/0/0"
>>> print(hd_priv.traverse(p2sh_p2wpkh_path).p2sh_p2wpkh_address())
2NBZYna15Fp45bFmice7Ld99B6HvwHRTNNz
>>> # p2wpkh
>>> p2wpkh_path = "m/84'/1'/0'/0/0"
>>> print(hd_priv.traverse(p2wpkh_path).bech32_address())
tb1qrpeej834jx0ll3euv86fg09865falq83zp7v27

#endcode
#unittest
hd:HDTest:test_get_address:
#endunittest
#exercise

#### Create external p2pkh, p2sh_p2wpkh and p2wpkh addresses

---
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # print the p2pkh address
>>> print(hd_priv.get_p2pkh_receiving_address())  #/
mpLAmKy2kMhTFSHRKcJzhdRTMjWYRp5rdt
>>> # print the p2sh-pwpkh address
>>> print(hd_priv.get_p2sh_p2wpkh_receiving_address())  #/
2NBZYna15Fp45bFmice7Ld99B6HvwHRTNNz
>>> # print the p2wpkh address
>>> print(hd_priv.get_p2wpkh_receiving_address())  #/
tb1qrpeej834jx0ll3euv86fg09865falq83zp7v27

#endexercise
#exercise

#### Create xpub for account 0

---
>>> from hd import HDPrivateKey
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> # create an HDPrivateKey instance using from_seed on testnet
>>> hd_priv = HDPrivateKey.from_seed(passphrase, testnet=True)  #/
>>> # calculate the path for purpose=44', coin=1' (testnet), account=0
>>> path = "m/44'/1'/0'"  #/
>>> # print the xpub at that path
>>> print(hd_priv.traverse(path).xpub())  #/
tpubDDNz9YHarfY2LUuBCMs9nw25BfE8LTjXe2YSuqqZCCk4JdvFswmPUa9myShQng1FxHs2Z1bV9Wik5oR69DjJkEsZn2co7ejVKup8iAMNWyc

#endexercise
#code

>>> def secure_mnemonic(entropy=0, num_bits=128):
...     # if we have more than 128 bits, just mask everything but the last 128 bits
...     if len(bin(entropy)) > num_bits+2:
...         entropy &= (1 << num_bits) - 1
...     # xor some random bits with the entropy that was passed in
...     preseed = randbits(num_bits) ^ entropy
...     # convert the number to big-endian
...     s = int_to_big_endian(preseed, 16)
...     # 1 extra bit for checksum is needed per 32 bits
...     checksum_bits_needed = num_bits // 32
...     # the checksum is the sha256's first n bits. At most this is 8
...     checksum = sha256(s)[0] >> (8 - checksum_bits_needed)
...     # we concatenate the checksum to the preseed
...     total = (preseed << checksum_bits_needed) | checksum
...     # now we get the mnemonic passphrase
...     mnemonic = []
...     # now group into groups of 11 bits
...     for _ in range((num_bits + bits_needed) // 11):
...         # grab the last 11 bits
...         current = total & ((1 << 11) - 1)
...         # insert the correct word at the front
...         mnemonic.insert(0, WORD_LIST[current])
...         # shift by 11 bits so we can move to the next set
...         total >>= 11
...     # return the mnemonic phrase by putting spaces between
...     return ' '.join(mnemonic)

#endcode
#code
>>> from hd import HDPrivateKey
>>> from helper import hmac_sha512_kdf, sha256
>>> from mnemonic import WORD_LOOKUP, WORD_LIST
>>> mnemonic = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
>>> password = b'TREZOR'
>>> words = mnemonic.split()
>>> if len(words) not in (12, 15, 18, 21, 24):
...     raise ValueError('you need 12, 15, 18, 21, or 24 words')
>>> number = 0
>>> for word in words:
...     index = WORD_LOOKUP[word]
...     number = (number << 11) | index
>>> checksum_bits_length = len(words) // 3
>>> checksum = number & ((1 << checksum_bits_length) - 1)
>>> data_num = number >> checksum_bits_length
>>> data = int_to_big_endian(data_num, checksum_bits_length * 4)
>>> computed_checksum = sha256(data)[0] >> (8 - checksum_bits_length)
>>> if checksum != computed_checksum:
...     raise ValueError('words fail checksum: {}'.format(words))
>>> normalized_words = []
>>> for word in words:
...     normalized_words.append(WORD_LIST[WORD_LOOKUP[word]])
>>> normalized_mnemonic = ' '.join(normalized_words)
>>> salt = b'mnemonic' + password
>>> seed = hmac_sha512_kdf(normalized_mnemonic, salt)
>>> print(HDPrivateKey.from_seed(seed).xprv())
xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq

#endcode
#unittest
hd:HDTest:test_from_mnemonic:
#endunittest
#exercise

#### Generate a testnet extended public key at m/84'/1'/0' using the generic mnemonic and your own passphrase

----
>>> from hd import HDPrivateKey
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song'  #/passphrase = b'<fill this in>'
>>> path = "m/84'/1'/0'"
>>> # create a private key using the mnemonic, passphrase, path and testnet=True
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, path, True)  #/
>>> # print the xpub
>>> print(hd_priv.xpub())  #/
tpubDD1e7uBTB1CxR8tJYsWswsrJob2R639TRSDgN3eyPyJJ6qoqZwHZ3GWdJ69Ppmpwy6aRhhQmx6WJt4mX7nwpVTU3HAAEY9gaJ32NnF9CjHQ

#endexercise
'''


from io import BytesIO
from unittest import TestCase

from ecc import G, N, PrivateKey, S256Point
from hd import (
    HDPrivateKey,
    HDPublicKey,
    MAINNET_XPRV,
    MAINNET_XPUB,
    MAINNET_YPRV,
    MAINNET_YPUB,
    MAINNET_ZPRV,
    MAINNET_ZPUB,
    TESTNET_XPRV,
    TESTNET_XPUB,
    TESTNET_YPRV,
    TESTNET_YPUB,
    TESTNET_ZPRV,
    TESTNET_ZPUB,
)
from helper import (
    big_endian_to_int,
    byte_to_int,
    encode_base58_checksum,
    hmac_sha512,
    hmac_sha512_kdf,
    int_to_big_endian,
    int_to_byte,
    raw_decode_base58,
    sha256,
)
from mnemonic import WORD_LOOKUP, WORD_LIST


def _get_address(self, purpose, account=0, external=True, address=0):
    if purpose not in ("44'", "49'", "84'"):
        raise ValueError('Cannot create an address without a proper purpose: {}'.format(purpose))
    if self.testnet:
        coin = "1'"
    else:
        coin = "0'"
    if external:
        chain = '0'
    else:
        chain = '1'
    path = "m/{}/{}/{}'/{}/{}".format(purpose, coin, account, chain, address)
    hd_priv = self.traverse(path)
    if purpose == "44'":
        return hd_priv.address()
    elif purpose == "49'":
        return hd_priv.p2sh_p2wpkh_address()
    elif purpose == "84'":
        return hd_priv.bech32_address()


def _prv(self, version):
    raw = version
    raw += int_to_byte(self.depth)
    raw += self.parent_fingerprint
    raw += int_to_big_endian(self.child_number, 4)
    raw += self.chain_code
    raw += int_to_big_endian(self.private_key.secret, 33)
    return encode_base58_checksum(raw)


def xprv_child(self, index):
    if index >= 0x80000000:
        data = int_to_big_endian(self.private_key.secret, 33) + int_to_big_endian(index, 4)
    else:
        data = self.private_key.point.sec() + int_to_big_endian(index, 4)
    h = hmac_sha512(self.chain_code, data)
    secret = (big_endian_to_int(h[:32]) + self.private_key.secret) % N
    private_key = PrivateKey(secret=secret)
    chain_code = h[32:]
    depth = self.depth + 1
    parent_fingerprint = self.pub.hash160()[:4]
    child_number = index
    return HDPrivateKey(
        private_key=private_key,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=self.testnet,
    )


@classmethod
def from_seed(cls, seed, testnet=False):
    h = hmac_sha512(b'Bitcoin seed', seed)
    private_key = PrivateKey(secret=big_endian_to_int(h[:32]))
    chain_code = h[32:]
    return cls(
        private_key=private_key,
        chain_code=chain_code,
        testnet=testnet,
    )


@classmethod
def from_mnemonic(cls, mnemonic, password=b'', path='m', testnet=False):
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError('you need 12, 15, 18, 21, or 24 words')
    number = 0
    for word in words:
        index = WORD_LOOKUP[word]
        number = (number << 11) | index
    checksum_bits_length = len(words) // 3
    checksum = number & ((1 << checksum_bits_length) - 1)
    data_num = number >> checksum_bits_length
    data = int_to_big_endian(data_num, checksum_bits_length * 4)
    computed_checksum = sha256(data)[0] >> (8 - checksum_bits_length)
    if checksum != computed_checksum:
        raise ValueError('words fail checksum: {}'.format(words))
    normalized_words = []
    for word in words:
        normalized_words.append(WORD_LIST[WORD_LOOKUP[word]])
    normalized_mnemonic = ' '.join(normalized_words)
    salt = b'mnemonic' + password
    seed = hmac_sha512_kdf(normalized_mnemonic, salt)
    return cls.from_seed(seed, testnet=testnet).traverse(path)


def xpub_child(self, index):
    if index >= 0x80000000:
        raise ValueError('child number should always be less than 2^31')
    data = self.point.sec() + int_to_big_endian(index, 4)
    h = hmac_sha512(key=self.chain_code, msg=data)
    point = self.point + big_endian_to_int(h[:32]) * G
    chain_code = h[32:]
    depth = self.depth + 1
    parent_fingerprint = self.fingerprint()
    child_number = index
    return HDPublicKey(
        point=point,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=self.testnet,
    )


@classmethod
def xprv_parse(cls, s):
    raw = raw_decode_base58(s)
    if len(raw) != 78:
        raise ValueError('Not a proper extended key')
    stream = BytesIO(raw)
    return cls.raw_parse(stream)

@classmethod
def xprv_raw_parse(cls, s):
    version = s.read(4)
    if version in (TESTNET_XPRV, TESTNET_YPRV, TESTNET_ZPRV):
        testnet = True
    elif version in (MAINNET_XPRV, MAINNET_YPRV, MAINNET_ZPRV):
        testnet = False
    else:
        raise ValueError('not an xprv, yprv or zprv: {}'.format(version))
    depth = byte_to_int(s.read(1))
    parent_fingerprint = s.read(4)
    child_number = big_endian_to_int(s.read(4))
    chain_code = s.read(32)
    if byte_to_int(s.read(1)) != 0:
        raise ValueError('private key should be preceded by a zero byte')
    private_key = PrivateKey(secret=big_endian_to_int(s.read(32)))
    return cls(
        private_key=private_key,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=testnet,
    )


def xprv_traverse(self, path):
    current = self
    components = path.split('/')[1:]
    for child in components:
        if child.endswith("'"):
            index = int(child[:-1]) + 0x80000000
        else:
            index = int(child)
        current = current.child(index)
    return current


def _serialize(self, version):
    raw = version
    raw += int_to_byte(self.depth)
    raw += self.parent_fingerprint
    raw += int_to_big_endian(self.child_number, 4)
    raw += self.chain_code
    raw += self.point.sec()
    return raw


def _pub(self, version):
    '''Returns the base58-encoded x/y/z pub.
    Expects a 4-byte version.'''
    raw = self._serialize(version)
    return encode_base58_checksum(raw)


@classmethod
def xpub_parse(cls, s):
    raw = raw_decode_base58(s)
    if len(raw) != 78:
        raise ValueError('Not a proper extended key')
    stream = BytesIO(raw)
    return cls.raw_parse(stream)


@classmethod
def xpub_raw_parse(cls, s):
    version = s.read(4)
    if version in (TESTNET_XPUB, TESTNET_YPUB, TESTNET_ZPUB):
        testnet = True
    elif version in (MAINNET_XPUB, MAINNET_YPUB, MAINNET_ZPUB):
        testnet = False
    else:
        raise ValueError('not an xpub, ypub or zpub: {} {}'.format(s, version))
    depth = byte_to_int(s.read(1))
    parent_fingerprint = s.read(4)
    child_number = big_endian_to_int(s.read(4))
    chain_code = s.read(32)
    point = S256Point.parse(s.read(33))
    return cls(
        point=point,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        testnet=testnet,
    )


def xpub_traverse(self, path):
    current = self
    components = path.split('/')[1:]
    for child in components:
        if child[-1:] == "'":
            raise ValueError('HDPublicKey cannot get hardened child')
        current = current.child(int(child))
    return current


class SessionTest(TestCase):

    def test_apply(self):
        HDPrivateKey._get_address = _get_address
        HDPrivateKey._prv = _prv
        HDPrivateKey.child = xprv_child
        HDPrivateKey.from_seed = from_seed
        HDPrivateKey.from_mnemonic = from_mnemonic
        HDPrivateKey.parse = xprv_parse
        HDPrivateKey.raw_parse = xprv_raw_parse
        HDPrivateKey.traverse = xprv_traverse
        HDPublicKey._pub = _pub
        HDPublicKey._serialize = _serialize
        HDPublicKey.child = xpub_child
        HDPublicKey.parse = xpub_parse
        HDPublicKey.raw_parse = xpub_raw_parse
        HDPublicKey.traverse = xpub_traverse
