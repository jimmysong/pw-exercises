'''
#code
>>> import psbt

#endcode
#exercise

#### Create a PSBT from the p2wpkh transaction you've been sent
---
>>> from io import BytesIO
>>> from psbt import PSBT
>>> from tx import Tx
>>> hex_tx = '01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef00000000'  #/hex_tx = '<fill this in>'
>>> # convert the hex transaction to a tx object
>>> tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)))  #/
>>> # use the create method to create a PSBT object
>>> psbt_obj = PSBT.create(tx_obj)  #/
>>> # serialize, turn to hex and print it to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef00000000000000

#endexercise
#code
>>> # example for updating the PSBT
>>> from helper import read_varstr
>>> from io import BytesIO
>>> from psbt import PSBT, PSBTIn, PSBTOut, NamedHDPublicKey
>>> from tx import Tx
>>> hex_named_hd = '4f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080'
>>> stream = BytesIO(bytes.fromhex(hex_named_hd))
>>> key = read_varstr(stream)
>>> named_hd = NamedHDPublicKey.parse(key, stream)
>>> hex_psbt = '70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac0000000000000000'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
>>> pubkey_lookup = named_hd.bip44_lookup()
>>> psbt_obj.update(tx_lookup, pubkey_lookup)
>>> print(psbt_obj.serialize().hex())
70736274ff0100770100000001192f88eeabc44ac213604adbb5b699678815d24b718b5940f5b1b1853f0887480100000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f0700000000001976a9144df14c8c8873451290c53e95ebd1ee8fe488f0ed88ac00000000000100fda40102000000000102816f71fa2b62d7235ae316d54cb174053c793d16644064405a8326094518aaa901000000171600148900fe9d1950305978d57ebbc25f722bbf131b53feffffff6e3e62f2e005db1bb2a1f12e5ca2bfbb4f82f2ca023c23b0a10a035cabb38fb60000000017160014ae01dce99edb5398cee5e4dc536173d35a9495a9feffffff0278de16000000000017a914a2be7a5646958a5b53f1c3de5a896f6c0ff5419f8740420f00000000001976a9149a9bfaf8ef6c4b061a30e8e162da3458cfa122c688ac02473044022017506b1a15e0540efe5453fcc9c61dcc4457dd00d22cba5e5b937c56944f96ff02207a1c071a8e890cf69c4adef5154d6556e5b356fc09d74a7c811484de289c2d41012102de6c105c8ed6c54d9f7a166fbe3012fecbf4bb3cecda49a8aad1d0c07784110c0247304402207035217de1a2c587b1aaeb5605b043189d551451697acb74ffc99e5a288f4fde022013b7f33a916f9e05846d333b6ea314f56251e74f243682e0ec45ce9e16c6344d01210205174b405fba1b53a44faf08679d63c871cece6c3b2c343bd2d7c559aa32dfb1a2271800220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c00008001000080000000800000000000000000000000

#endcode
#unittest
psbt:PSBTTest:test_update_p2wpkh:
#endunittest
#exercise

#### Update the PSBT that you got.

----
>>> from helper import read_varstr
>>> from hd import HDPrivateKey
>>> from io import BytesIO
>>> from psbt import PSBT, PSBTIn, PSBTOut, NamedHDPublicKey
>>> from tx import Tx
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> path = "m/44'/1'/0'"
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)
>>> hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef00000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # create the NamedHDPublicKey using the HDPrivateKey and path
>>> named_hd = NamedHDPublicKey.from_hd_priv(hd_priv, path)  #/
>>> # get the tx lookup using the psbt_obj's tx_object's get_input_tx_lookup method
>>> tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()  #/
>>> # get the pubkey lookup using the bip44_lookup method
>>> pubkey_lookup = named_hd.bip44_lookup()  #/
>>> # update the psbt object with the transaction lookup and the pubkey lookup
>>> psbt_obj.update(tx_lookup, pubkey_lookup)  #/
>>> # print the serialized hex to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000

#endexercise
#unittest
psbt:PSBTTest:test_sign_p2wpkh:
#endunittest
#exercise

#### Sign the PSBT that you got.

----
>>> from helper import read_varstr
>>> from hd import HDPrivateKey
>>> from io import BytesIO
>>> from psbt import PSBT, PSBTIn, PSBTOut, NamedHDPublicKey
>>> from tx import Tx
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> path = "m/44'/1'/0'"
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)
>>> hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # use the HDPrivateKey to sign the PSBT
>>> psbt_obj.sign(hd_priv)  #/
True
>>> # print the serialized hex to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e0122060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000

#endexercise
#unittest
psbt:PSBTTest:test_finalize_p2wpkh:
#endunittest
#unittest
psbt:PSBTTest:test_final_tx_p2wpkh:
#endunittest
#exercise

#### Finalize, Extract and Broadcast the PSBT that you got.

----
>>> from psbt import PSBT
>>> hex_psbt = '70736274ff01005201000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef000000000001011f40420f0000000000160014f0cd79383f13584bdeca184cecd16135b8a79fc222020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e0122060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000002202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c0000800100008000000080010000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # finalize the PSBT
>>> psbt_obj.finalize()  #/
>>> # extract the transaction using final_tx
>>> tx_obj = psbt_obj.final_tx()  #/
>>> # breadcast the transaction
>>> print(tx_obj.serialize().hex())  #/
010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060000000000ffffffff01583e0f000000000016001427459b7e4317d1c9e1d0f8320d557c6bb08731ef024730440220575870ef714252a26bc4e61a6ee31db0f3896606a4792d11a42ef7d30c9f1b33022007cd28fb8618b704cbcf1cc6292d9be901bf3c99d967b0cace7307532619811e01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f200000000

#endexercise
#unittest
psbt:NamedHDPublicKeyTest:test_redeem_script_lookup:
#endunittest
#unittest
psbt:PSBTTest:test_p2sh_p2wpkh:
#endunittest
#exercise

#### You have been sent an empty p2sh-p2wpkh transaction. Update, sign, finalize, extract and broadcast the signed transaction.

----
>>> from helper import read_varstr
>>> from hd import HDPrivateKey
>>> from io import BytesIO
>>> from psbt import PSBT, PSBTIn, PSBTOut, NamedHDPublicKey
>>> from tx import Tx
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> path = "m/44'/1'/0'"
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)
>>> hex_tx = '01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000'  #/hex_tx = '<fill this in>'
>>> # convert the hex transaction to a tx object
>>> tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)))  #/
>>> # use the create method to create a PSBT object
>>> psbt_obj = PSBT.create(tx_obj)  #/
>>> psbt_obj.tx_obj.testnet = True
>>> # create the NamedHDPublicKey using the HDPrivateKey and path
>>> named_hd = NamedHDPublicKey.from_hd_priv(hd_priv, path)  #/
>>> # get the tx lookup using the psbt_obj's tx_object's get_input_tx_lookup method
>>> tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()  #/
>>> # get the pubkey lookup using the bip44_lookup method
>>> pubkey_lookup = named_hd.bip44_lookup()  #/
>>> # get the RedeemScript lookup using the redeem_script_lookup method
>>> redeem_script_lookup = named_hd.redeem_script_lookup()  #/
>>> # update the psbt object with the transaction lookup and the pubkey lookup
>>> psbt_obj.update(tx_lookup, pubkey_lookup, redeem_script_lookup)  #/
>>> # use the HDPrivateKey to sign the PSBT
>>> psbt_obj.sign(hd_priv)  #/
True
>>> # finalize the PSBT
>>> psbt_obj.finalize()  #/
>>> # extract the transaction using final_tx
>>> tx_obj = psbt_obj.final_tx()  #/
>>> # breadcast the transaction
>>> print(tx_obj.serialize().hex())  #/
010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060100000017160014f0cd79383f13584bdeca184cecd16135b8a79fc2ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7502483045022100f332008498ada0d5c83717c638b6d9f2bc6b79e657ab1db0bd45538e1390905202203060d6ffa36bb49b3469ea806a03644958926d56dda96701e7eaa3ca5320c49f01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f200000000

#endexercise
#code
>>> # example of updating
>>> from helper import serialize_binary_path, encode_varstr
>>> from io import BytesIO
>>> from psbt import PSBT
>>> from script import WitnessScript
>>> hex_psbt = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000000'
>>> hex_witness_scripts = ['47522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae', '47522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae']
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
>>> key_1 = bytes.fromhex('02043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af')
>>> key_2 = bytes.fromhex('02043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f753393')
>>> path = "m/44'/1'/0'"
>>> stream_1 = BytesIO(encode_varstr(bytes.fromhex('fbfef36f') + serialize_binary_path(path)))
>>> stream_2 = BytesIO(encode_varstr(bytes.fromhex('797dcdac') + serialize_binary_path(path)))
>>> hd_1 = NamedHDPublicKey.parse(key_1, stream_1)
>>> hd_2 = NamedHDPublicKey.parse(key_2, stream_2)
>>> pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}
>>> witness_lookup = {}
>>> for hex_witness_script in hex_witness_scripts:
...     witness_script = WitnessScript.parse(BytesIO(bytes.fromhex(hex_witness_script)))
...     witness_lookup[witness_script.sha256()] = witness_script
>>> psbt_obj.update(tx_lookup, pubkey_lookup, witness_lookup=witness_lookup)
>>> print(psbt_obj.serialize().hex())
70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000

#endcode
#unittest
psbt:PSBTTest:test_update_p2wsh:
#endunittest
#exercise

#### Update the transaction that's been given to you

----
>>> from helper import serialize_binary_path, encode_varstr
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> from script import WitnessScript
>>> hex_psbt = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000000'
>>> hex_witness_scripts = ['47522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae', '47522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae']
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> path = "m/44'/1'/0'"
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)
>>> # get the tx lookup using get_input_tx_lookup
>>> tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()  #/
>>> hd_1 = list(psbt_obj.hd_pubs.values())[0]
>>> hd_2 = NamedHDPublicKey.from_hd_priv(hd_priv, path)
>>> pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}
>>> witness_lookup = {}
>>> for hex_witness_script in hex_witness_scripts:
...     witness_script = WitnessScript.parse(BytesIO(bytes.fromhex(hex_witness_script)))
...     witness_lookup[witness_script.sha256()] = witness_script
>>> psbt_obj.update(tx_lookup, pubkey_lookup, witness_lookup=witness_lookup)
>>> print(psbt_obj.serialize().hex())
70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000

#endexercise
#exercise

#### Sign the transaction with your HD private key

----
>>> from helper import serialize_binary_path, encode_varstr
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> hex_psbt = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> path = "m/44'/1'/0'"
>>> # get the private key using the mnemonic, passphrase and testnet=True
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)  #/
>>> # sign the psbt
>>> print(psbt_obj.sign(hd_priv))  #/
True
>>> # print the serialized hex of the PSBT to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d22020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f247304402204fd654c27002d4c9e53bb001229e3d7587e5be245a81b6f7ead3bf136643af40022060ebf1193a6b3e82615a564f0043e5ae88e661bfdb7fd254c9a30bae8160583901010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000

#endexercise
#unittest
psbt:PSBTTest:test_finalize_p2wsh:
#endunittest
#exercise

#### Finalize, extract and broadcast the PSBT

----
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> hex_psbt = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c00008001000080000000800001012b40420f0000000000220020c1b4fff485af1ac26714340af2e13d2e89ad70389332a0756d91a123c7fe7f5d220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402203f26a975aae04a7ae12c964cdcea318c850351a3072aebbab7902e89957008ea022019f895271f70d1515f9da776d6ac17c21bcbca769d87c1beb4ebbf4c7a56fbc20122020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f247304402204fd654c27002d4c9e53bb001229e3d7587e5be245a81b6f7ead3bf136643af40022060ebf1193a6b3e82615a564f0043e5ae88e661bfdb7fd254c9a30bae8160583901010547522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010147522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # finalize
>>> psbt_obj.finalize()  #/
>>> # get the final Tx
>>> final_tx = psbt_obj.final_tx()  #/
>>> # print the tx serialized hex to see what it looks like
>>> print(final_tx.serialize().hex())  #/
010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060200000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c040047304402203f26a975aae04a7ae12c964cdcea318c850351a3072aebbab7902e89957008ea022019f895271f70d1515f9da776d6ac17c21bcbca769d87c1beb4ebbf4c7a56fbc20147304402204fd654c27002d4c9e53bb001229e3d7587e5be245a81b6f7ead3bf136643af40022060ebf1193a6b3e82615a564f0043e5ae88e661bfdb7fd254c9a30bae816058390147522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae00000000

#endexercise
#endunittest
#unittest
psbt:PSBTTest:test_p2sh_p2wsh:
#endunittest
#exercise

#### Combine, update, sign, finalize, extract and finalize the PSBTs sent to you

----
>>> from hd import HDPrivateKey
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> hex_psbt_1 = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c835073872202031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b483045022100e7dc3213aff7676be5bc087fe1698b1b04e53555f93bb11478bd22c0b6a6ffe502205c86c17bcb4d9bf7bd7ae82f18af5f7f387f72c82af27ecd4b9f6b68f2f2821b0101042200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38010569532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000002206031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b18fbfef36f2c000080010000800000008000000000010000000000'  #/hex_psbt_1 = '<fill this in>'
>>> hex_psbt_2 = '70736274ff01005e01000000015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f9060300000000ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c000000000001012040420f000000000017a91423358e259fbcf478331138ceb9619d9a8c83507387220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c4830450221008c892608dcbbc5b40fc40a82bb4bdeeb79f4a81b4a8d26d0915d2ba2c3d84a28022076d5507bf6ad60893e9baaf7690823d5c85a8720abab7bb48a64449c1b5c9ff50101042200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38010569532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000002206031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b18fbfef36f2c000080010000800000008000000000010000000000'  #/hex_psbt_2 = '<fill this in>'
>>> psbt_obj_1 = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt_1)))
>>> psbt_obj_1.tx_obj.testnet = True
>>> psbt_obj_2 = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt_2)))
>>> psbt_obj_2.tx_obj.testnet = True
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> path = "m/44'/1'/0'"
>>> # get the private key using the mnemonic, passphrase and testnet=True
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)  #/
>>> # create the NamedHDPublicKey using the HDPrivateKey and path
>>> named_hd = NamedHDPublicKey.from_hd_priv(hd_priv, path)  #/
>>> # combine the two objects
>>> psbt_obj_1.combine(psbt_obj_2)  #/
>>> # grab the pubkey lookup using bip44_lookup
>>> pubkey_lookup = named_hd.bip44_lookup()  #/
>>> # update the PSBT
>>> psbt_obj_1.update({}, pubkey_lookup)  #/
>>> # sign the psbt
>>> print(psbt_obj_1.sign(hd_priv))  #/
True
>>> # finalize the transaction
>>> psbt_obj_1.finalize()  #/
>>> # get the final Tx
>>> final_tx = psbt_obj_1.final_tx()  #/
>>> # print the tx serialized hex to see what it looks like
>>> print(final_tx.serialize().hex())  #/
010000000001015c89191dc2abf62339e0f114cb4c3bf8fb399d522d112c9afa2dc7a43759f90603000000232200207fcc2ca7381db4bdfd02e1f2b5eb3d72435b8e09bdbd8bfe3d748bf19d78ef38ffffffff01583e0f0000000000220020878ce58b26789632a24ec6b62542e5d4e844dee56a7ddce7db41618049c3928c05004830450221008c892608dcbbc5b40fc40a82bb4bdeeb79f4a81b4a8d26d0915d2ba2c3d84a28022076d5507bf6ad60893e9baaf7690823d5c85a8720abab7bb48a64449c1b5c9ff501483045022100e7dc3213aff7676be5bc087fe1698b1b04e53555f93bb11478bd22c0b6a6ffe502205c86c17bcb4d9bf7bd7ae82f18af5f7f387f72c82af27ecd4b9f6b68f2f2821b01483045022100981caa0b9e5ebe5e125e913b03b0fd4fd4b3545b7aabfb06994389991d27584802206a80027d7cc16a7fe94dd847f3038d080f7edbc983f47dd7c8b5b295bbe614740169532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae00000000

#endexercise
'''

from unittest import TestCase

from helper import op_code_to_number
from psbt import NamedHDPublicKey, PSBT, PSBTIn, PSBTOut
from script import RedeemScript, Script
from witness import Witness


def redeem_script_lookup(self, max_external=9, max_internal=9):
    lookup = {}
    external = self.child(0)
    for child_index in range(max_external+1):
        child = external.child(child_index)
        redeem_script = RedeemScript([0, child.hash160()])
        lookup[redeem_script.hash160()] = redeem_script
    internal = self.child(1)
    for child_index in range(max_internal+1):
        child = internal.child(child_index)
        redeem_script = RedeemScript([0, child.hash160()])
        lookup[redeem_script.hash160()] = redeem_script
    return lookup


def final_tx(self):
    tx_obj = self.tx_obj.clone()
    if any([psbt_in.witness for psbt_in in self.psbt_ins]):
        tx_obj.segwit = True
    for tx_in, psbt_in in zip(tx_obj.tx_ins, self.psbt_ins):
        tx_in.script_sig = psbt_in.script_sig
        if tx_obj.segwit:
            tx_in.witness = psbt_in.witness or Witness()
    if not tx_obj.verify():
        raise RuntimeError('transaction invalid')
    return tx_obj


def sign(self, hd_priv):
    signed = False
    fingerprint = hd_priv.fingerprint()
    for i, psbt_in in enumerate(self.psbt_ins):
        for named_pub in psbt_in.named_pubs.values():
            if named_pub.root_fingerprint == fingerprint:
                private_key = hd_priv.traverse(named_pub.root_path).private_key
                if psbt_in.prev_tx:
                    sig = self.tx_obj.get_sig_legacy(i, private_key, psbt_in.redeem_script)
                    psbt_in.sigs[private_key.point.sec()] = sig
                elif psbt_in.prev_out:
                    sig = self.tx_obj.get_sig_segwit(i, private_key, psbt_in.redeem_script, psbt_in.witness_script)
                    psbt_in.sigs[private_key.point.sec()] = sig
                else:
                    raise ValueError('pubkey included without the previous output')
                signed = True
    return signed


def finalize(self):
    script_pubkey = self.script_pubkey()
    if script_pubkey.is_p2sh():
        if not self.redeem_script:
            raise RuntimeError('Cannot finalize p2sh without a RedeemScript')
    if script_pubkey.is_p2wpkh() or (self.redeem_script and self.redeem_script.is_p2wpkh()):
        if len(self.sigs) != 1:
            raise RuntimeError('p2wpkh or p2sh-p2wpkh should have exactly 1 signature')
        sec = list(self.sigs.keys())[0]
        sig = list(self.sigs.values())[0]
        if self.redeem_script:
            self.script_sig = Script([self.redeem_script.raw_serialize()])
        else:
            self.script_sig = Script()
        self.witness = Witness([sig, sec])
    elif script_pubkey.is_p2wsh() or (self.redeem_script and self.redeem_script.is_p2wsh()):
        if not self.witness_script:
            raise RuntimeError('Cannot finalize p2wsh or p2sh-p2wsh without a WitnessScript')
        num_sigs = op_code_to_number(self.witness_script.commands[0])
        if len(self.sigs) < num_sigs:
            raise RuntimeError('Cannot finalize p2wsh or p2sh-p2wsh because {} sigs were provided where {} were needed'.format(len(self.sigs), num_sigs))
        witness_items = [b'\x00']
        for command in self.witness_script.commands:
            sig = self.sigs.get(command)
            if sig is not None:
                witness_items.append(sig)
            if len(witness_items) - 1 >= num_sigs:
                break
        if len(witness_items) - 1 < num_sigs:
            raise RuntimeError('Not enough signatures provided for p2sh-p2wsh')
        witness_items.append(self.witness_script.raw_serialize())
        self.witness = Witness(witness_items)
        if self.redeem_script:
            self.script_sig = Script([self.redeem_script.raw_serialize()])
        else:
            self.script_sig = Script()
    elif script_pubkey.is_p2sh():
        num_sigs = op_code_to_number(self.redeem_script.commands[0])
        if len(self.sigs) < num_sigs:
            raise RuntimeError('Cannot finalize p2sh because {} sigs were provided where {} were needed'.format(len(self.sigs), num_sigs))
        script_sig_commands = [0]
        for command in self.redeem_script.commands:
            if type(command) == int:
                continue
            sig = self.sigs.get(command)
            if sig is not None:
                script_sig_commands.append(sig)
            if len(script_sig_commands) - 1 >= num_sigs:
                break
        if len(script_sig_commands) < num_sigs:
            raise RuntimeError('Not enough signatures provided for p2wsh')
        script_sig_commands.append(self.redeem_script.raw_serialize())
        self.script_sig = Script(script_sig_commands)
    elif script_pubkey.is_p2pkh():
        if len(self.sigs) != 1:
            raise RuntimeError('P2pkh requires exactly 1 signature')
        sec = list(self.sigs.keys())[0]
        sig = list(self.sigs.values())[0]
        self.script_sig = Script([sig, sec])
    else:
        raise ValueError('Cannot finalize this ScriptPubKey: {}'.format(script_pubkey))
    self.sigs = {}
    self.hash_type = None
    self.redeem_script = None
    self.witness_script = None
    self.named_pubs = {}


def psbtin_update(self, tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup):
    prev_tx = self.prev_tx or tx_lookup.get(self.tx_in.prev_tx)
    if prev_tx:
        prev_out = prev_tx.tx_outs[self.tx_in.prev_index]
    else:
        prev_out = self.prev_out
    if not prev_tx and not prev_out:
        return
    script_pubkey = prev_out.script_pubkey
    self.tx_in._value = prev_out.amount
    self.tx_in._script_pubkey = script_pubkey
    if script_pubkey.is_p2sh():
        self.redeem_script = self.redeem_script or redeem_lookup.get(script_pubkey.commands[1])
        if not self.redeem_script:
            return
    if script_pubkey.is_p2wpkh() or \
       (self.redeem_script and self.redeem_script.is_p2wpkh()):
        self.prev_out = prev_out
        if script_pubkey.is_p2wpkh():
            h160 = script_pubkey.commands[1]
        else:
            h160 = self.redeem_script.commands[1]
        named_pub = pubkey_lookup.get(h160)
        if named_pub:
            self.named_pubs[named_pub.sec()] = named_pub.point
    elif script_pubkey.is_p2wsh() or (self.redeem_script and self.redeem_script.is_p2wsh()):
        self.prev_out = prev_out
        if script_pubkey.is_p2wsh():
            s256 = script_pubkey.commands[1]
        else:
            s256 = self.redeem_script.commands[1]
        self.witness_script = self.witness_script or witness_lookup.get(s256)
        if self.witness_script:
            for command in self.witness_script.commands:
                named_pub = pubkey_lookup.get(command)
                if named_pub:
                    self.named_pubs[named_pub.sec()] = named_pub.point
    elif script_pubkey.is_p2sh():
        self.prev_tx = prev_tx
        for command in self.redeem_script.commands:
            named_pub = pubkey_lookup.get(command)
            if named_pub:
                self.named_pubs[named_pub.sec()] = named_pub.point
    elif script_pubkey.is_p2pkh():
        self.prev_tx = prev_tx
        named_pub = pubkey_lookup.get(script_pubkey.commands[2])
        if named_pub:
            self.named_pubs[named_pub.sec()] = named_pub.point
    else:
        raise ValueError('cannot update a transaction because it is not p2pkh, p2sh, p2wpkh or p2wsh'.format(script_pubkey))


def psbtout_update(self, pubkey_lookup, redeem_lookup, witness_lookup):
    script_pubkey = self.tx_out.script_pubkey
    if script_pubkey.is_p2sh():
        self.redeem_script = redeem_lookup.get(script_pubkey.commands[1])
        if not self.redeem_script:
            return
    if script_pubkey.is_p2wpkh() or (self.redeem_script and self.redeem_script.is_p2wpkh()):
        if self.redeem_script:
            h160 = self.redeem_script.commands[1]
        else:
            h160 = script_pubkey.commands[1]
        named_pub = pubkey_lookup.get(h160)
        if named_pub:
            self.named_pubs[named_pub.sec()] = named_pub.point
    elif script_pubkey.is_p2wsh() or (self.redeem_script and self.redeem_script.is_p2wsh()):
        if self.redeem_script:
            s256 = self.redeem_script.commands[1]
        else:
            s256 = script_pubkey.commands[1]
        witness_script = witness_lookup.get(s256)
        if witness_script:
            self.witness_script = witness_script
            for command in witness_script.commands:
                named_pub = pubkey_lookup.get(command)
                if named_pub:
                    self.named_pubs[named_pub.sec()] = named_pub.point
    elif script_pubkey.is_p2sh():
        for command in self.redeem_script.commands:
            named_pub = pubkey_lookup.get(command)
            if named_pub:
                self.named_pubs[named_pub.sec()] = named_pub.point
    elif script_pubkey.is_p2pkh():
        named_pub = pubkey_lookup.get(script_pubkey.commands[2])
        if named_pub:
            self.named_pubs[named_pub.sec()] = named_pub.point


class SessionTest(TestCase):

    def test_apply(self):
        NamedHDPublicKey.redeem_script_lookup = redeem_script_lookup
        PSBT.final_tx = final_tx
        PSBT.sign = sign
        PSBTIn.finalize = finalize
        PSBTIn.update = psbtin_update
        PSBTOut.update = psbtout_update
