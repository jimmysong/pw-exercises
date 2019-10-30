'''
#code
>>> import psbt, script, tx

#endcode
#code
>>> # example creating a PSBT
>>> from io import BytesIO
>>> from psbt import PSBT, PSBTIn, PSBTOut
>>> from script import Script
>>> from tx import Tx
>>> from witness import Witness
>>> hex_tx = '0100000001af70eeccc0098dc1b5c319bbb24fad1e7539ff59f58ddd9ff03b54a0e47c54f70000000000ffffffff014c400f00000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac00000000'
>>> tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)), testnet=True)
>>> psbt_ins = []
>>> for tx_in in tx_obj.tx_ins:
...     if tx_in.script_sig.commands:
...         script_sig = tx_in.script_sig
...         tx_in.script_sig = Script()
...     else:
...         script_sig = None
...     psbt_in = PSBTIn(tx_in, script_sig=script_sig)
...     psbt_ins.append(psbt_in)
>>> psbt_outs = []
>>> for tx_out in tx_obj.tx_outs:
...     psbt_out = PSBTOut(tx_out)
...     psbt_outs.append(psbt_out)
>>> psbt_obj = PSBT(tx_obj, psbt_ins, psbt_outs)
>>> print(psbt_obj.serialize().hex())
70736274ff0100550100000001af70eeccc0098dc1b5c319bbb24fad1e7539ff59f58ddd9ff03b54a0e47c54f70000000000ffffffff014c400f00000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac00000000000000

#endcode
#unittest
psbt:PSBTTest:test_create:
#endunittest
#exercise

#### Create a PSBT from the transaction you've been sent
---
>>> from io import BytesIO
>>> from psbt import PSBT
>>> from tx import Tx
>>> hex_tx = '010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000'  #/hex_tx = '<fill this in>'
>>> # convert the hex transaction to a tx object
>>> tx_obj = Tx.parse(BytesIO(bytes.fromhex(hex_tx)))  #/
>>> # if you completed the previous exercise, use the create method
>>> psbt_obj = PSBT.create(tx_obj)  #/
>>> # serialize, turn to hex and print it to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff010052010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000000

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
psbt:PSBTTest:test_update_p2pkh:
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
>>> hex_psbt = '70736274ff010052010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000000'  #/hex_psbt = '<fill this in>'
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
70736274ff010052010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000100e20100000000010154eec2c506b426d06cbb3f8dd9ee0694140e6309609fcb0924c2aeac6559c2a60100000000ffffffff0240420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac784eba01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750248304502210085a3ede2ba3069ee972cd6d6ea03598c146e8ad4100b1377ae97c454f76ed0d8022040d7c9379a7ed8b4f3fd382ca65877e805e47be9f08d20388f3a1c2e3d90c41e0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e0000000022060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000

#endexercise
#unittest
psbt:PSBTTest:test_sign_p2pkh:
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
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)
>>> hex_psbt = '70736274ff010052010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000100e20100000000010154eec2c506b426d06cbb3f8dd9ee0694140e6309609fcb0924c2aeac6559c2a60100000000ffffffff0240420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac784eba01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750248304502210085a3ede2ba3069ee972cd6d6ea03598c146e8ad4100b1377ae97c454f76ed0d8022040d7c9379a7ed8b4f3fd382ca65877e805e47be9f08d20388f3a1c2e3d90c41e0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e0000000022060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # use the HDPrivateKey to sign the PSBT
>>> psbt_obj.sign(hd_priv)  #/
True
>>> # print the serialized hex to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff010052010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000100e20100000000010154eec2c506b426d06cbb3f8dd9ee0694140e6309609fcb0924c2aeac6559c2a60100000000ffffffff0240420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac784eba01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750248304502210085a3ede2ba3069ee972cd6d6ea03598c146e8ad4100b1377ae97c454f76ed0d8022040d7c9379a7ed8b4f3fd382ca65877e805e47be9f08d20388f3a1c2e3d90c41e0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e0000000022020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24830450221008d9cbe9ab11a0cc29ace2d85c846e67c428268d9232975e53d88d32bebd7e77c0220043b5496fe4b9f1891117554d3789574bc94737aba0a5485b93b9bf82d2030ad0122060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000

#endexercise
#unittest
psbt:PSBTTest:test_finalize_p2pkh:
#endunittest
#unittest
psbt:PSBTTest:test_final_tx:
#endunittest
#exercise

#### Finalize, Extract and Broadcast the PSBT that you got.

----
>>> from psbt import PSBT
>>> hex_psbt = '70736274ff010052010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850000000000ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000000100e20100000000010154eec2c506b426d06cbb3f8dd9ee0694140e6309609fcb0924c2aeac6559c2a60100000000ffffffff0240420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac784eba01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750248304502210085a3ede2ba3069ee972cd6d6ea03598c146e8ad4100b1377ae97c454f76ed0d8022040d7c9379a7ed8b4f3fd382ca65877e805e47be9f08d20388f3a1c2e3d90c41e0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e0000000022020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f24830450221008d9cbe9ab11a0cc29ace2d85c846e67c428268d9232975e53d88d32bebd7e77c0220043b5496fe4b9f1891117554d3789574bc94737aba0a5485b93b9bf82d2030ad0122060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c000080010000800000008000000000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # finalize the PSBT
>>> psbt_obj.finalize()  #/
>>> # extract the transaction using final_tx
>>> tx_obj = psbt_obj.final_tx()  #/
>>> # breadcast the transaction
>>> print(tx_obj.serialize().hex())  #/
010000000187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d8485000000006b4830450221008d9cbe9ab11a0cc29ace2d85c846e67c428268d9232975e53d88d32bebd7e77c0220043b5496fe4b9f1891117554d3789574bc94737aba0a5485b93b9bf82d2030ad01210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2ffffffff01583e0f00000000001600146e13971913b9aa89659a9f53d327baa8826f2d7500000000

#endexercise
#code
>>> # example of updating
>>> from helper import serialize_binary_path, encode_varstr
>>> from io import BytesIO
>>> from psbt import PSBT
>>> from script import RedeemScript
>>> hex_psbt = '70736274ff01007501000000015c59ecb919792ecc26e031e9f4a6d4d74afce7b17dfe039002ef82b1f30bb63e0000000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f07000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b870000000000000000'
>>> hex_redeem_scripts = ['47522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae', '47522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae']
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> tx_lookup = psbt_obj.tx_obj.get_input_tx_lookup()
>>> key_1 = bytes.fromhex('02043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af')
>>> key_2 = bytes.fromhex('02043587cf0398242fbc80000000959cb81379545d7a34287f41485a3c08fc6ecf66cb89caff8a4f618b484d6e7d0362f19f492715b6041723d97403f166da0e3246eb614d80635c036a8d2f753393')
>>> stream_1 = BytesIO(encode_varstr(bytes.fromhex('fbfef36f') + serialize_binary_path("m/44'/1'/0'")))
>>> stream_2 = BytesIO(encode_varstr(bytes.fromhex('797dcdac') + serialize_binary_path("m/44'/1'/0'")))
>>> hd_1 = NamedHDPublicKey.parse(key_1, stream_1)
>>> hd_2 = NamedHDPublicKey.parse(key_2, stream_2)
>>> pubkey_lookup = {**hd_1.bip44_lookup(), **hd_2.bip44_lookup()}
>>> redeem_lookup = {}
>>> for hex_redeem_script in hex_redeem_scripts:
...     redeem_script = RedeemScript.parse(BytesIO(bytes.fromhex(hex_redeem_script)))
...     redeem_lookup[redeem_script.hash160()] = redeem_script
>>> psbt_obj.update(tx_lookup, pubkey_lookup, redeem_lookup)
>>> print(psbt_obj.serialize().hex())
70736274ff01007501000000015c59ecb919792ecc26e031e9f4a6d4d74afce7b17dfe039002ef82b1f30bb63e0000000000ffffffff0220a10700000000001976a91426d5d464d148454c76f7095fdf03afc8bc8d82c388ac2c9f07000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b8700000000000100fda201020000000001024b9f6ab9def1aabadd74f37c61361d4c555c08b3518b0f393e0df037a538058b010000001716001446fe25a61b6afad8e8619854ec65eaa5a3d707c2feffffff03df61643d0f37ca92b9e67d94d7acffb58bf167b3a73692ff2ca1933b51123f0100000017160014a77769eca770c1cafbcfa7bb06e44a7fc3748ef5feffffff0240420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee87966f1b000000000017a914f10824ee9939fa638b9cc75e516408dc1d9fe248870247304402205c5f2ed7d4ce4da4913ee08b1413a7f0dadd8c59c6fe9c94fe299c8a7456076102203abb3b6f895938bf489a2473591877c7aa2cc7fddb1ca2e9632294b06d80f3a90121025ab592b2533bc8a4e4b3b52794b5f2318850c004b3dc24099271fb7db080ef820247304402204f57bbd3cc35c15bc7de0a8890c656d5608ab41c731c64413c45730fb0b05a5c0220162c676a55b2ff349cbea7d1908f034443419e30caf20a47beb5f209116cb0c3012102fed02d7c44b8bb82f23948e26e005572ff08fec43d6094daf67d2bc691f4d64d9f271800010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000

#endcode
#unittest
psbt:PSBTTest:test_update_p2sh:
#endunittest
#exercise

#### Update the transaction that's been given to you

----
>>> from helper import serialize_binary_path, encode_varstr
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> from script import RedeemScript
>>> hex_psbt = '70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000000'
>>> hex_redeem_scripts = ['47522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae', '47522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae']
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
>>> redeem_lookup = {}
>>> for hex_redeem_script in hex_redeem_scripts:
...     redeem_script = RedeemScript.parse(BytesIO(bytes.fromhex(hex_redeem_script)))
...     redeem_lookup[redeem_script.hash160()] = redeem_script
>>> psbt_obj.update(tx_lookup, pubkey_lookup, redeem_lookup)
>>> print(psbt_obj.serialize().hex())
70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000100fd01010100000000010187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850100000000ffffffff0340420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac10c69b01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750247304402204edcdf923bdddad9b77b17ae0c65817f032b7cb6efd95c0c4101fa48aba17e4e02202158c3a077a0ee0a7bc7e2763a9356470ae3aa4866ae4e62a6f8faa2729b02da0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e00000000010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000

#endexercise
#exercise

#### Sign the transaction with your HD private key

----
>>> from helper import serialize_binary_path, encode_varstr
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> hex_psbt = '70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000100fd01010100000000010187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850100000000ffffffff0340420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac10c69b01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750247304402204edcdf923bdddad9b77b17ae0c65817f032b7cb6efd95c0c4101fa48aba17e4e02202158c3a077a0ee0a7bc7e2763a9356470ae3aa4866ae4e62a6f8faa2729b02da0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e00000000220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402207360ee58276e8135ae1efdf1bbd7b3d87d1c7f072f3141cfe8afa78f3e36cdf7022059462d2e4598e3b441fa2503eb73b6d6b644838d3c9af547f09760b0655ce93801010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
>>> passphrase = b'jimmy@programmingblockchain.com Jimmy Song 2'  #/passphrase = b'<fill this in>'
>>> # get the private key using the mnemonic, passphrase and testnet=True
>>> hd_priv = HDPrivateKey.from_mnemonic(mnemonic, passphrase, testnet=True)  #/
>>> # sign the psbt
>>> print(psbt_obj.sign(hd_priv))  #/
True
>>> # print the serialized hex of the PSBT to see what it looks like
>>> print(psbt_obj.serialize().hex())  #/
70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000100fd01010100000000010187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850100000000ffffffff0340420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac10c69b01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750247304402204edcdf923bdddad9b77b17ae0c65817f032b7cb6efd95c0c4101fa48aba17e4e02202158c3a077a0ee0a7bc7e2763a9356470ae3aa4866ae4e62a6f8faa2729b02da0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e00000000220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402207360ee58276e8135ae1efdf1bbd7b3d87d1c7f072f3141cfe8afa78f3e36cdf7022059462d2e4598e3b441fa2503eb73b6d6b644838d3c9af547f09760b0655ce9380122020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2473044022038c818f86a2cb1e092c55f2e30c74904c4ebbf80805ba7235369b626444ff7a402202594d8fa4f855be4dbecc148804056c2938218e7fe1a7b805a0d18f2d47a31e801010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000

#endexercise
#unittest
psbt:PSBTTest:test_finalize_p2sh:
#endunittest
#exercise

#### Finalize, extract and broadcast the PSBT

----
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> hex_psbt = '70736274ff0100530100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b0000000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b87000000004f01043587cf034d513c1580000000fb406c9fec09b6957a3449d2102318717b0c0d230b657d0ebc6698abd52145eb02eaf3397fea02c5dac747888a9e535eaf3c7e7cb9d5f2da77ddbdd943592a14af10fbfef36f2c0000800100008000000080000100fd01010100000000010187a22bb77a836c0a3bbb62e1e04950cffdf6a45489a8d7801b24b18c124d84850100000000ffffffff0340420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288ac10c69b01000000001600146e13971913b9aa89659a9f53d327baa8826f2d750247304402204edcdf923bdddad9b77b17ae0c65817f032b7cb6efd95c0c4101fa48aba17e4e02202158c3a077a0ee0a7bc7e2763a9356470ae3aa4866ae4e62a6f8faa2729b02da0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e00000000220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c47304402207360ee58276e8135ae1efdf1bbd7b3d87d1c7f072f3141cfe8afa78f3e36cdf7022059462d2e4598e3b441fa2503eb73b6d6b644838d3c9af547f09760b0655ce9380122020247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f2473044022038c818f86a2cb1e092c55f2e30c74904c4ebbf80805ba7235369b626444ff7a402202594d8fa4f855be4dbecc148804056c2938218e7fe1a7b805a0d18f2d47a31e801010447522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252ae22060247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f218797dcdac2c00008001000080000000800000000000000000220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c0000800100008000000080000000000000000000010047522102db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29021026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d52ae2202026421c7673552fdad57193e102df96134be00649195b213fec9d07c6d918f418d18797dcdac2c00008001000080000000800100000000000000220202db8b701c3210e1bf6f2a8a9a657acad18be1e8bff3f7435d48f973de8408f29018fbfef36f2c0000800100008000000080010000000000000000'  #/hex_psbt = '<fill this in>'
>>> psbt_obj = PSBT.parse(BytesIO(bytes.fromhex(hex_psbt)))
>>> psbt_obj.tx_obj.testnet = True
>>> # finalize
>>> psbt_obj.finalize()  #/
>>> # get the final Tx
>>> final_tx = psbt_obj.final_tx()  #/
>>> # print the tx serialized hex to see what it looks like
>>> print(final_tx.serialize().hex())  #/
0100000001e8be6d62ba1983b5d1c65406f87f7d73c2d7200d4075cf52589c53579870542b00000000d90047304402207360ee58276e8135ae1efdf1bbd7b3d87d1c7f072f3141cfe8afa78f3e36cdf7022059462d2e4598e3b441fa2503eb73b6d6b644838d3c9af547f09760b0655ce93801473044022038c818f86a2cb1e092c55f2e30c74904c4ebbf80805ba7235369b626444ff7a402202594d8fa4f855be4dbecc148804056c2938218e7fe1a7b805a0d18f2d47a31e80147522102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f252aeffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b8700000000

#endexercise
#unittest
psbt:PSBTTest:test_combine:
#endunittest
#exercise

#### Combine and finalize the transaction

----
>>> from hd import HDPrivateKey
>>> from io import BytesIO
>>> from psbt import NamedHDPublicKey, PSBT
>>> hex_psbt_1 = '70736274ff01005301000000016f0a34017a8777b9b68178ef19553cb35ee8f8087fc1513d4e78f1d7908428ff0100000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b8700000000000100fd2201010000000001011c6bbc28989a0be9b7bf9f3790a7a4f39b77ac5c4e4084672e31c48699a8f7be0300000000ffffffff0440420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f000000000017a9148fb8b8f8f1d5d9292ebeb765622a50e5eee5e1068740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288acc0304001000000001600146e13971913b9aa89659a9f53d327baa8826f2d7502483045022100a9968c79bdf4d18534995614864109646f0525dba7f557bc840dcadc4ac9fd07022075167f8cbbade9722b08ab4ccf297acf8ce4d47d1f2c61eadc21f453d274fd7e0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e00000000220202c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c473044022048654296cf5dd26306757f6df7a86dad698eacff246045e34ab5b5ea448fa456022008d7cf3fe54c8b56128622384bffc43b4cdee714e23c9d7e25bb5afcd0667a5f01010469532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000002206031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b18fbfef36f2c000080010000800000008000000000010000000000'  #/hex_psbt_1 = '<fill this in>'
>>> hex_psbt_2 = '70736274ff01005301000000016f0a34017a8777b9b68178ef19553cb35ee8f8087fc1513d4e78f1d7908428ff0100000000ffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b8700000000000100fd2201010000000001011c6bbc28989a0be9b7bf9f3790a7a4f39b77ac5c4e4084672e31c48699a8f7be0300000000ffffffff0440420f000000000017a914c5bea2bad6a3171dff5fad0b99d2e60fca1d8bee8740420f000000000017a9148fb8b8f8f1d5d9292ebeb765622a50e5eee5e1068740420f00000000001976a914f0cd79383f13584bdeca184cecd16135b8a79fc288acc0304001000000001600146e13971913b9aa89659a9f53d327baa8826f2d7502483045022100a9968c79bdf4d18534995614864109646f0525dba7f557bc840dcadc4ac9fd07022075167f8cbbade9722b08ab4ccf297acf8ce4d47d1f2c61eadc21f453d274fd7e0121031dbe3aff7b9ad64e2612b8b15e9f5e4a3130663a526df91abfb7b1bd16de5d6e000000002202031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b483045022100e91ed50b397f4f252ea358905e245e9c78758c54aeebbbff903003f442c13413022018d467d17b2880699c3dcd30b26ce80ce9be503454731c0e919701ad4031b90201010469532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253ae220602c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c18fbfef36f2c000080010000800000008000000000000000002206031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b18fbfef36f2c000080010000800000008000000000010000000000'  #/hex_psbt_2 = '<fill this in>'
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
01000000016f0a34017a8777b9b68178ef19553cb35ee8f8087fc1513d4e78f1d7908428ff01000000fd460100473044022048654296cf5dd26306757f6df7a86dad698eacff246045e34ab5b5ea448fa456022008d7cf3fe54c8b56128622384bffc43b4cdee714e23c9d7e25bb5afcd0667a5f01483045022100e91ed50b397f4f252ea358905e245e9c78758c54aeebbbff903003f442c13413022018d467d17b2880699c3dcd30b26ce80ce9be503454731c0e919701ad4031b90201483045022100f44c5799caa012f02809ec0322ae780b80b190b9eb27dce81c20641d2b7fa9d502207125ac947d871480ed2eb3eac7db6dd2607f817756c678e020d0375977dbba43014c69532102c1b6ac6e6a625fee295dc2d580f80aae08b7e76eca54ae88a854e956095af77c21031b31547c895b5e301206740ea9890a0d6d127baeebb7fffb07356527323c915b210247aed77c3def4b8ce74a8db08d7f5fd315f8d96b6cd801729a910c3045d750f253aeffffffff01583e0f000000000017a91481a19f39772bd741501e851e97ddd6a7f1ec194b8700000000

#endexercise
'''

from unittest import TestCase

from helper import (
    op_code_to_number,
)
from psbt import PSBT, PSBTIn, PSBTOut
from script import Script
from witness import Witness


@classmethod
def create(cls, tx_obj):
    psbt_ins = []
    for tx_in in tx_obj.tx_ins:
        if tx_in.script_sig.commands:
            script_sig = tx_in.script_sig
            tx_in.script_sig = Script()
        else:
            script_sig = None
        if tx_in.witness:
            witness = tx_in.witness
            tx_in.witness = Witness()
        else:
            witness = None
        psbt_in = PSBTIn(tx_in, script_sig=script_sig, witness=witness)
        psbt_ins.append(psbt_in)
    psbt_outs = []
    for tx_out in tx_obj.tx_outs:
        psbt_out = PSBTOut(tx_out)
        psbt_outs.append(psbt_out)
    return cls(tx_obj, psbt_ins, psbt_outs)


def final_tx(self):
    tx_obj = self.tx_obj.clone()
    if any([psbt_in.witness for psbt_in in self.psbt_ins]):
        tx_obj.segwit = True
    for tx_in, psbt_in in zip(tx_obj.tx_ins, self.psbt_ins):
        tx_in.script_sig = psbt_in.script_sig
        if tx_obj.segwit:
            tx_in.witness = psbt_in.witness
    if not tx_obj.verify():
        raise RuntimeError('transaction invalid')
    return tx_obj


def psbt_combine(self, other):
    if self.tx_obj.hash() != other.tx_obj.hash():
        raise ValueError('cannot combine PSBTs that refer to different transactions')
    self.hd_pubs = {**other.hd_pubs, **self.hd_pubs}
    self.extra_map = {**other.extra_map, **self.extra_map}
    for psbt_in_1, psbt_in_2 in zip(self.psbt_ins, other.psbt_ins):
        psbt_in_1.combine(psbt_in_2)
    for psbt_out_1, psbt_out_2 in zip(self.psbt_outs, other.psbt_outs):
        psbt_out_1.combine(psbt_out_2)


def psbt_finalize(self):
    for psbt_in in self.psbt_ins:
        psbt_in.finalize()


def psbt_update(self, tx_lookup, pubkey_lookup, redeem_lookup=None, witness_lookup=None):
    if redeem_lookup is None:
        redeem_lookup = {}
    if witness_lookup is None:
        witness_lookup = {}
    for psbt_in in self.psbt_ins:
        psbt_in.update(tx_lookup, pubkey_lookup, redeem_lookup, witness_lookup)
    for psbt_out in self.psbt_outs:
        psbt_out.update(pubkey_lookup, redeem_lookup, witness_lookup)


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
                else:
                    raise ValueError('pubkey included without the previous output')
                signed = True
    return signed


def psbtin_combine(self, other):
    if self.prev_tx is None and other.prev_tx:
        self.prev_tx = other.prev_tx
    if self.prev_out is None and other.prev_out:
        self.prev_out = other.prev_out
    self.sigs = {**self.sigs, **other.sigs}
    if self.hash_type is None and other.hash_type:
        self.hash_type = other.hash_type
    if self.redeem_script is None and other.redeem_script:
        self.redeem_script = other.redeem_script
    if self.witness_script is None and other.witness_script:
        self.witness_script = other.witness_script
    self.named_pubs = {**other.named_pubs, **self.named_pubs}
    if self.script_sig is None and other.script_sig:
        self.script_sig = other.script_sig
    if self.witness is None and other.witness:
        self.witness = other.witness
    self.extra_map = {**other.extra_map, **self.extra_map}


def psbtin_finalize(self):
    script_pubkey = self.script_pubkey()
    if script_pubkey.is_p2sh():
        if not self.redeem_script:
            raise RuntimeError('Cannot finalize p2sh without a RedeemScript {}'.format(self))
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
        self.prev_tx = prev_tx
        self.redeem_script = self.redeem_script or redeem_lookup.get(script_pubkey.commands[1])
        if not self.redeem_script:
            return
        for command in self.redeem_script.commands:
            hd_pub = pubkey_lookup.get(command)
            if hd_pub:
                self.named_pubs[hd_pub.sec()] = hd_pub.point
    elif script_pubkey.is_p2pkh():
        self.prev_tx = prev_tx
        hd_pub = pubkey_lookup.get(script_pubkey.commands[2])
        if hd_pub:
            self.named_pubs[hd_pub.sec()] = hd_pub.point
    else:
        raise ValueError('cannot update a transaction because it is not p2pkh or p2sh'.format(script_pubkey))


def psbtout_combine(self, other):
    if self.redeem_script is None and other.redeem_script:
        self.redeem_script = other.redeem_script
    if self.witness_script is None and other.witness_script:
        self.witness_script = other.witness_script
    self.named_pubs = {**other.named_pubs, **self.named_pubs}
    self.extra_map = {**other.extra_map, **self.extra_map}


def psbtout_update(self, pubkey_lookup, redeem_lookup, witness_lookup):
    script_pubkey = self.tx_out.script_pubkey
    if script_pubkey.is_p2sh():
        self.redeem_script = redeem_lookup.get(script_pubkey.commands[1])
        if not self.redeem_script:
            return
        for command in self.redeem_script.commands:
            hd_pub = pubkey_lookup.get(command)
            if hd_pub:
                self.named_pubs[hd_pub.sec()] = hd_pub.point
    elif script_pubkey.is_p2pkh():
        hd_pub = pubkey_lookup.get(script_pubkey.commands[2])
        if hd_pub:
            self.named_pubs[hd_pub.sec()] = hd_pub.point


class SessionTest(TestCase):

    def test_apply(self):
        PSBT.combine = psbt_combine
        PSBT.create = create
        PSBT.finalize = psbt_finalize
        PSBT.final_tx = final_tx
        PSBT.sign = sign
        PSBT.update = psbt_update
        PSBTIn.combine = psbtin_combine
        PSBTIn.finalize = psbtin_finalize
        PSBTIn.update = psbtin_update
        PSBTOut.combine = psbtout_combine
        PSBTOut.update = psbtout_update
