"""
#markdown
# Tagged Hashes
* Each hash is different so that hashes cannot feasibly collide
* There are 10 different contexts, each creating its own set of hashes
* The hash is SHA256, but with 64 bytes before the actual bytes being hashed
* The 64 bytes are another SHA256 of the tag (e.g. "BIP340/aux") repeated twice
* H_aux(x) = SHA256(SHA256("BIP340/aux") + SHA256("BIP340/aux") + x)
#endmarkdown
#code
>>> import ecc
>>> import hash
>>> import op
>>> import taproot

#endcode
#code
>>> # Example Tagged Hashes
>>> from hash import sha256
>>> challenge_tag = b"BIP0340/challenge"
>>> msg = b"some message"
>>> challenge_hash = sha256(challenge_tag)
>>> hash_challenge = sha256(challenge_hash + challenge_hash + msg)
>>> print(hash_challenge.hex())
233a1e9353c5f782c96c1c08323fe9fca47ad161ee69d008846b68625c221113

#endcode
#exercise

What is the tagged hash "BIP0340/aux" of "hello world"?

----

>>> from hash import sha256
>>> # define the challenge tag and the message
>>> challenge_tag = b"BIP0340/aux"  #/
>>> msg = b"hello world"  #/
>>> # calculate the challenge tag hash using sha256
>>> challenge_tag_hash = sha256(challenge_tag)  #/
>>> # calculate the hash of the challenge
>>> hash_challenge = sha256(challenge_tag_hash + challenge_tag_hash + msg)  #/
>>> print(hash_challenge.hex())  #/
1d721a19d161e978e7436d9e73bb810a0a32cbdffc7a9b29e11713b1940a4126

#endexercise
#unittest
hash:HashTest:test_tagged_hash:
#endunittest
#markdown
# $x$-only keys
* Assume $y$ is even
* Serialized as 32-bytes
* The private key $e$ is flipped to $N-e$ if $y$ is odd
* $eG=P=(x,y)$ means $(N-e)G=0-eG=-P=(x,-y)$
* Lots of flipping!
#endmarkdown
#code
>>> # Example X-only pubkey
>>> from ecc import PrivateKey, S256Point
>>> from helper import int_to_big_endian
>>> pubkey = PrivateKey(12345).point
>>> xonly = int_to_big_endian(pubkey.x.num, 32)
>>> print(xonly.hex())
f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f

>>> pubkey2 = S256Point.parse(xonly)
>>> print(pubkey.xonly() == pubkey2.xonly())
True

#endcode
#exercise
Find the $x$-only pubkey format for the private key with the secret 21,000,000

---
>>> from ecc import PrivateKey
>>> secret = 21000000
>>> # create a private key with the secret
>>> priv = PrivateKey(secret)  #/
>>> # get the public point for the private key
>>> point = priv.point  #/
>>> # convert the x coordinate to a big-endian integer 32 bytes
>>> xonly = int_to_big_endian(point.x.num, 32)  #/
>>> print(xonly.hex())  #/
e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291

#endexercise
#unittest
ecc:XOnlyTest:test_xonly:
#endunittest
#markdown
# Schnorr Verification
* $eG=P$, $m$ message, $kG=R$, $H$ is a hash function
* Signature is $(R,s)$ where $s=k + e H(R||P||m)$
* $$-H(R||P||m)P+sG \\ =-H(R||P||m)P+(k+e H(R||P||m))G \\ =-H(R||P||m)P+kG+H(R||P||m)(eG) \\ =R+H(R||P||m)P-H(R||P||m)P=R$$
#endmarkdown
#code
>>> from ecc import S256Point, SchnorrSignature, G, N
>>> from helper import sha256, big_endian_to_int
>>> from hash import hash_challenge
>>> # the message we're signing
>>> msg = sha256(b"I attest to understanding Schnorr Signatures")
>>> # the signature we're using
>>> sig_raw = bytes.fromhex("f3626c99fe36167e5fef6b95e5ed6e5687caa4dc828986a7de8f9423c0f77f9bc73091ed86085ce43de0e255b3d0afafc7eee41ddc9970c3dc8472acfcdfd39a")
>>> sig = SchnorrSignature.parse(sig_raw)
>>> # the pubkey we are using
>>> xonly = bytes.fromhex("f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")
>>> point = S256Point.parse(xonly)
>>> # calculate the commitment which is R || P || msg
>>> commitment = sig.r.xonly() + point.xonly() + msg
>>> # hash_challenge the commitment, interpret as big endian and mod by N
>>> challenge = big_endian_to_int(hash_challenge(commitment)) % N
>>> # the target is the -challenge * point + s * G
>>> target = -challenge * point + sig.s * G
>>> print(target == sig.r)
True

#endcode
#exercise

Verify this Schnorr Signature

Pubkey = cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91
Signature = 2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4
Message = 1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612

---
>>> from ecc import SchnorrSignature, S256Point, N, G
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> p_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> pubkey = S256Point.parse(p_raw)
>>> sig_raw = bytes.fromhex("2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4")
>>> sig = SchnorrSignature.parse(sig_raw)
>>> msg = bytes.fromhex("1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612")
>>> # create the commitment: R || P || m (points should be xonly)
>>> commitment = sig.r.xonly() + pubkey.xonly() + msg  #/
>>> # hash the commitment with hash_challenge and then big_endian_to_int it
>>> h = big_endian_to_int(hash_challenge(commitment))  #/
>>> # check that -hP+sG=R
>>> print(-h*pubkey + sig.s*G  == sig.r)  #/
True

#endexercise
#unittest
ecc:SchnorrTest:test_verify:
#endunittest
#markdown
# Schnorr Signing
* $eG=P$, $m$ message, $k$ random
* $kG=R$, $H$ is a hash function
* $s=k+e H(R||P||m)$ where $R$ and $P$ are $x$-only
* Signature is $(R,s)$
#endmarkdown
#code
>>> # Example Signing
>>> from ecc import PrivateKey, N, G
>>> from helper import sha256, big_endian_to_int
>>> priv = PrivateKey(12345)
>>> if priv.point.y.num % 2 == 1:
...     d = N - priv.secret
... else:
...     d = priv.secret
>>> msg = sha256(b"I attest to understanding Schnorr Signatures")
>>> k = 21016020145315867006318399104346325815084469783631925097217883979013588851039
>>> r = k * G
>>> if r.y.num % 2 == 1:
...     k = N - k
...     r = k * G
>>> commitment = r.xonly() + priv.point.xonly() + msg
>>> e = big_endian_to_int(hash_challenge(commitment)) % N
>>> s = (k + e * d) % N
>>> sig = SchnorrSignature(r, s)
>>> if not priv.point.verify_schnorr(msg, sig):
...     raise RuntimeError("Bad Signature")
>>> print(sig.serialize().hex())
f3626c99fe36167e5fef6b95e5ed6e5687caa4dc828986a7de8f9423c0f77f9bc73091ed86085ce43de0e255b3d0afafc7eee41ddc9970c3dc8472acfcdfd39a

#endcode
#exercise

Sign the message b"I'm learning Taproot!" with the private key 21,000,000

----

>>> from ecc import PrivateKey, N, G
>>> from helper import sha256
>>> # create the private key
>>> priv = PrivateKey(21000000)  #/
>>> # calculate d (working secret) based on whether the y is even or odd
>>> if priv.point.y.num % 2 == 1:
...     d = N - priv.secret
... else:
...     d = priv.secret
>>> # create the message
>>> msg = sha256(b"I'm learning Taproot!")  #/
>>> # We'll learn more about k later, for now use 987654321
>>> k = 987654321
>>> # get the resulting R=kG point
>>> r = k * G  #/
>>> # if R's y coordinate is odd, flip the k
>>> if r.y.num % 2 == 1:  #/
...     # set k to N - k
...     k = N - k  #/
...     # recalculate R
...     r = k * G  #/
>>> # calculate the commitment which is: R || P || msg
>>> commitment = r.xonly() + priv.point.xonly() + msg  #/
>>> # hash_challenge the result and interpret as a big endian integer mod the result by N and this is your e
>>> e = big_endian_to_int(hash_challenge(commitment)) % N  #/
>>> # calculate s which is (k+ed) mod N
>>> s = (k + e * d) % N  #/
>>> # create a SchnorrSignature object using the R and s
>>> sig = SchnorrSignature(r, s)  #/
>>> # check that this schnorr signature verifies
>>> if not priv.point.verify_schnorr(msg, sig):  #/
...     raise RuntimeError("Bad Signature")  #/
>>> # print the serialized hex of the signature
>>> print(sig.serialize().hex())  #/
5ad2703f5b4f4b9dea4c28fa30d86d3781d28e09dd51aae1208de80bb6155bee7d9dee36de5540efd633445a8d743816cbbc15fb8a1c7768984190d5b873a341

#endexercise
#unittest
ecc:SchnorrTest:test_sign:
#endunittest
#markdown
# Batch Verification
* $e_iG=P_i$, $m_i$ message, $H$
* Signature is $(R_i,s_i)$, $h_i=H(R_i||P_i||m_i)$
* $-h_i P_1+s_1G=R_1$
* $-h_i P_2+s_2G=R_2$
* $-h_1 P_1-h_2 P_1+(s_1+s_2)G=R_1+R_2$
* $(s_1+s_2)G=R_1+R_2+h_1 P_1+h_2 P_2$
#endmarkdown
#exercise

Batch Verify these two Schnorr Signatures

Pubkey 1 = cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91
Pubkey 2 = e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291

Signature 1 = 2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4
Signature 2 = b6e52f38bc24f1420c4fdae8fa0f04b9b0374a12f18fd4699b06df53eb1386bfa88c1835cd19470cf8c76550eb549c988f9c8fac00cc56fadd4fcc3bf9d8800e

Message 1 = 1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612
Message 2 = af1c325abcb0cced3a4166ce67be1db659ae1dd574fe49b0f2941d8d4882d62c

---
>>> from ecc import SchnorrSignature, S256Point, N, G
>>> from hash import hash_challenge
>>> from helper import big_endian_to_int
>>> p1_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> p2_raw = bytes.fromhex("e79c4eb45764bd015542f6779cc70fef44b7a2432f839264768288efab886291")
>>> p1 = S256Point.parse(p1_raw)
>>> p2 = S256Point.parse(p2_raw)
>>> sig1_raw = bytes.fromhex("2ae68f873376a0ff302258964632f7b98b21e3bbc72dcc8fb31de8acf01696b951f3dbb6fc5532558219472fb63e061f9a4c7d1760cc588da551c74374cd0de4")
>>> sig2_raw = bytes.fromhex("b6e52f38bc24f1420c4fdae8fa0f04b9b0374a12f18fd4699b06df53eb1386bfa88c1835cd19470cf8c76550eb549c988f9c8fac00cc56fadd4fcc3bf9d8800e")
>>> sig1 = SchnorrSignature.parse(sig1_raw)
>>> sig2 = SchnorrSignature.parse(sig2_raw)
>>> msg1 = bytes.fromhex("1a84547db188f0b1d2c9f0beac230afebbd5e6e6c1a46fc69841815194bf8612")
>>> msg2 = bytes.fromhex("af1c325abcb0cced3a4166ce67be1db659ae1dd574fe49b0f2941d8d4882d62c")
>>> # define s as the s_i sum (make sure to mod by N)
>>> s = (sig1.s + sig2.s) % N  #/
>>> # define r as the signatures' r sum
>>> r = sig1.r + sig2.r  #/
>>> # create the commitments: R_i||P_i||m_i
>>> commitment_1 = sig1.r.xonly() + p1.xonly() + msg1  #/
>>> commitment_2 = sig2.r.xonly() + p2.xonly() + msg2  #/
>>> # define the h's as the hash_challenge of the commitment as a big endian integer
>>> h1 = big_endian_to_int(hash_challenge(commitment_1))  #/
>>> h2 = big_endian_to_int(hash_challenge(commitment_2))  #/
>>> # compute the sum of the h_i P_i's
>>> h = h1*p1 + h2*p2  #/
>>> # check that sG=R+h
>>> print(s*G == r+h)  #/
True

#endexercise
#markdown
# How to spend from the KeyPath
* You have to know the Merkle Root of the ScriptPath
* The internal public key is hashed together with the Merkle Root to generate the tweak $t$
* The formula is $t=H(P||t)$ where H is a Tagged Hash (TapTweak)
* $Q=P+tG$, and $eG=P$ which means $Q=eG+tG$ and $Q=(e+t)G$
* $e+t$ is your private key, which can sign for the public key Q
* Witness only needs the Schnorr Signature
* If you don't want a script path, $t$ is just empty
#endmarkdown
#code
>>> # Example Q calculation for a single-key
>>> from ecc import S256Point, G
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from script import P2TRScriptPubKey
>>> internal_pubkey_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> internal_pubkey = S256Point.parse(internal_pubkey_raw)
>>> tweak = big_endian_to_int(hash_taptweak(internal_pubkey_raw))
>>> external_pubkey = internal_pubkey + tweak * G
>>> script_pubkey = P2TRScriptPubKey(external_pubkey)
>>> print(script_pubkey)
OP_1 578444b411276eee17e2f69988d192b7e728f4375525a868f4a9c2b78e12af16

#endcode
#exercise

Make a P2TR ScriptPubKey using the private key 9284736473

----
>>> from ecc import PrivateKey, G
>>> from hash import hash_taptweak
>>> from helper import big_endian_to_int
>>> from script import P2TRScriptPubKey
>>> priv = PrivateKey(9284736473)
>>> # get the internal pubkey
>>> internal_pubkey = priv.point  #/
>>> # calculate the tweak
>>> tweak = big_endian_to_int(hash_taptweak(internal_pubkey.xonly()))  #/
>>> # Q = P + tG
>>> external_pubkey = internal_pubkey + tweak * G  #/
>>> # use P2TRScriptPubKey to create the ScriptPubKey
>>> script_pubkey = P2TRScriptPubKey(external_pubkey)  #/
>>> # print the ScriptPubKey
>>> print(script_pubkey)  #/
OP_1 a6b9f4b7999f9c6de76165342c9feac354d5d3062a41761ed1616eaf9e3c38ec

#endexercise
#unittest
ecc:TapRootTest:test_default_tweak:
#endunittest
#unittest
ecc:TapRootTest:test_tweaked_key:
#endunittest
#unittest
ecc:TapRootTest:test_p2tr_script:
#endunittest
#markdown
# P2TR Addresses
* Uses Bech32m, which is different than Bech32 (BIP350)
* Segwit v0 uses Bech32
* Taproot (Segwit v1) uses Bech32m
* Has error correcting capability and uses 32 letters/numbers
* Segwit v0 addresses start with bc1q and p2wpkh is shorter than p2wsh
* Segwit v1 addresses start with bc1p and they're all one length
#endmarkdown
#code
>>> # Example of getting a p2tr address
>>> from ecc import S256Point
>>> internal_pubkey_raw = bytes.fromhex("cbaa648dbfe734646ce958e2f14a874149fae4010fdeabde4bae6a732537fd91")
>>> internal_pubkey = S256Point.parse(internal_pubkey_raw)
>>> print(internal_pubkey.p2tr_address())
bc1p27zyfdq3yahwu9lz76vc35vjklnj3aph25j6s68548pt0rsj4utql46j72

>>> print(internal_pubkey.p2tr_address(network="signet"))
tb1p27zyfdq3yahwu9lz76vc35vjklnj3aph25j6s68548pt0rsj4utqgavay9

#endcode
#exercise

Make your own Signet P2TR Address

Write down your address at [this link](https://docs.google.com/spreadsheets/d/1wUNeR-g5qY_2lh18gxg5JIQr352fOW2wZia_QErj4V0/edit?usp=sharing) under "keypath address"

----
>>> from ecc import PrivateKey
>>> from helper import sha256
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_secret = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> # create the private key object
>>> priv = PrivateKey(my_secret)  #/
>>> # get the public point
>>> point = priv.point  #/
>>> # print the p2tr_address with network set to "signet"
>>> print(point.p2tr_address(network="signet"))  #/
tb1pfx2ys8pzcg0mdufk9v25hphv85zgjpv5kyn6uevdmfmvdsw0ea0qyvv87u

#endexercise
#markdown
# Spending plan
* We have 20,000 sats in this output: 871864d7631024465fc210e553fa9f50e7f0f2359288ad121aa733d65e366995:0
* We want to spend all of it to tb1ptaqplrhnyh3kq85n7dtm5vcpgstt0ev80f4wd8ngeppch4fzu8mquchufq
* 1 input/1 output transaction
#endmarkdown
#code
>>> # Spending from a p2tr
>>> from ecc import PrivateKey, N
>>> from helper import sha256, big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from tx import Tx, TxIn, TxOut
>>> my_email = b"jimmy@programmingblockchain.com"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> priv = PrivateKey(my_secret)
>>> prev_tx = bytes.fromhex("871864d7631024465fc210e553fa9f50e7f0f2359288ad121aa733d65e366995")
>>> prev_index = 0
>>> target_address = "tb1ptaqplrhnyh3kq85n7dtm5vcpgstt0ev80f4wd8ngeppch4fzu8mquchufq"
>>> fee = 500
>>> tx_in = TxIn(prev_tx, prev_index)
>>> target_script_pubkey = address_to_script_pubkey(target_address)
>>> target_amount = tx_in.value(network="signet") - fee
>>> tx_out = TxOut(target_amount, target_script_pubkey)
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)
>>> tweaked_secret = (priv.secret + big_endian_to_int(priv.point.tweak())) % N
>>> tweaked_key = PrivateKey(tweaked_secret)
>>> tx_obj.sign_p2tr_keypath(0, tweaked_key)
True
>>> print(tx_obj.serialize().hex())
010000000001019569365ed633a71a12ad889235f2f0e7509ffa53e510c25f46241063d76418870000000000ffffffff012c4c0000000000002251205f401f8ef325e3601e93f357ba33014416b7e5877a6ae69e68c8438bd522e1f601403697a0f0f49a451668b9b0361ec7c3b857299f0f80b8ce8c50e1d3cc87f44382de2b6eeccabe0efda3b1639841c342fce64ba28a2a018d4a9a69f5e7a0d43f6b00000000

#endcode
#unittest
ecc:PrivateKeyTest:test_tweaked_key:
#endunittest
#exercise

## Checkpoint Exercise

You have been sent 100,000 sats to your address on Signet. Send 40,000 sats back to <code>tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg</code>, the rest to yourself.

Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction

----

>>> from ecc import PrivateKey
>>> from helper import sha256
>>> from script import address_to_script_pubkey
>>> from tx import Tx, TxIn, TxOut
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_secret = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> priv = PrivateKey(my_secret)  #/
>>> prev_tx = bytes.fromhex("25096348891ff6b120b88c944501791f8809698474569cc994d63dc5bcfe6a37")  #/prev_tx = bytes.fromhex("<fill in from block explorer>")
>>> target_address = "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
>>> target_amount = 40000
>>> fee = 500
>>> # fill this in from the block explorer
>>> prev_index = 0  #/prev_index = -1
>>> # create the one input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # use the address_to_script_pubkey to get the ScriptPubKey
>>> target_script_pubkey = address_to_script_pubkey(target_address)  #/
>>> # create the target output
>>> tx_out_1 = TxOut(target_amount, target_script_pubkey)  #/
>>> # calculate the change amount
>>> change_amount = 100000 - target_amount - fee  #/
>>> # use the private key's point's p2tr_script method to get the change ScriptPubkey
>>> change_script_pubkey = priv.point.p2tr_script()  #/
>>> # create the change output
>>> tx_out_2 = TxOut(change_amount, change_script_pubkey)  #/
>>> # create the transaction
>>> tx_obj = Tx(1, [tx_in], [tx_out_1, tx_out_2], network="signet", segwit=True)  #/
>>> # sign the transaction using the tweaked key and the sign_p2tr_keypath method
>>> tx_obj.sign_p2tr_keypath(0, priv.tweaked_key())  #/
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())  #/
01000000000101376afebcc53dd694c99c5674846909881f790145948cb820b1f61f89486309250000000000ffffffff02409c000000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d72146ce80000000000002251204994481c22c21fb6f1362b154b86ec3d04890594b127ae658dda76c6c1cfcf5e014002de2a8a88783937f10742235dfdf6a0f9526f4e8eee9d3d4cd11d5813269a0d1b56b5028b81735dae9d3dd9b9f2fe2193474dba0569cff087c2575f0f8f5b5f00000000

#endexercise
#markdown
# OP_CHECKSIGADD
* Consumes the top three elements: a pubkey, a number, and a signature.
* Valid sig, returns the number+1 to the stack
* Invalid sig, returns the number back to the stack
#endmarkdown
#unittest
op:TapScriptTest:test_opchecksigadd:
#endunittest
#markdown
# Example TapScripts
* 1-of-1 (pay-to-pubkey) [pubkey, OP_CHECKSIG]
* 2-of-2 [pubkey A, OP_CHECKSIGVERIFY, pubkey B, OP_CHECKSIG]
* 2-of-3 [pubkey A, OP_CHECKSIG, pubkey B, OP_CHECKSIGADD, pubkey C, OP_CHECKSIGADD, OP_2, OP_EQUAL]
* halvening timelock 1-of-1 [840000, OP_CHECKLOCKTIMEVERIFY, OP_DROP, pubkey, OP_CHECKSIG]
#endmarkdown
#code
>>> # Example TapScripts
>>> from ecc import PrivateKey
>>> from op import encode_minimal_num
>>> from taproot import TapScript
>>> pubkey_a = PrivateKey(11111111).point.xonly()
>>> pubkey_b = PrivateKey(22222222).point.xonly()
>>> pubkey_c = PrivateKey(33333333).point.xonly()
>>> # 1-of-1 (0xAC is OP_CHECKSIG)
>>> tap_script = TapScript([pubkey_a, 0xAC])
>>> print(tap_script)
331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIG

>>> # 2-of-2 (0xAD is OP_CHECKSIGVERIFY)
>>> tap_script = TapScript([pubkey_a, 0xAD, pubkey_b, 0xAC])
>>> print(tap_script)
331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIGVERIFY 158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f OP_CHECKSIG

>>> # 2-of-3 (0xBA is OP_CHECKSIGADD, 0x52 is OP_2, 0x87 is OP_EQUAL)
>>> tap_script = TapScript([pubkey_a, 0xAD, pubkey_b, 0xBA, pubkey_c, 0xBA, 0x52, 0x87])
>>> print(tap_script)
331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIGVERIFY 158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f OP_CHECKSIGADD 582662e8e47df59489d6756615aa3db3fa3bbaa75a424b9c78036265858f5544 OP_CHECKSIGADD OP_2 OP_EQUAL

>>> # halvening timelock 1-of-1 (0xB1 is OP_CLTV, 0x75 is OP_DROP)
>>> tap_script = TapScript([encode_minimal_num(840000), 0xB1, 0x75, pubkey_a, 0xAC])
>>> print(tap_script)
40d10c OP_CHECKLOCKTIMEVERIFY OP_DROP 331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec OP_CHECKSIG

#endcode
#exercise

Make a TapScript for 4-of-4 using pubkeys from private keys which correspond to 10101, 20202, 30303, 40404

----
>>> from ecc import PrivateKey
>>> from taproot import TapScript
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create a 4-of-4 tapscript that uses OP_CHECKSIGVERIFY (0xad) and OP_CHECKSIG (0xac)
>>> tap_script = TapScript([pubkey_1, 0xAD, pubkey_2, 0xAD, pubkey_3, 0xAD, pubkey_4, 0xAC])  #/
>>> # print the TapScript
>>> print(tap_script)  #/
134ba4d9c35a66017e9d525a879700a9fb9209a3f43a651fdaf71f3a085a77d3 OP_CHECKSIGVERIFY 027aa71d9cdb31cd8fe037a6f441e624fe478a2deece7affa840312b14e971a4 OP_CHECKSIGVERIFY 165cfd87a31d8fab4431c955b0462804f1ba79b41970ab7e8b0e4e4686f5f8b4 OP_CHECKSIGVERIFY 9e5f5a5c29d33c32185a3dc0a9ccb3e72743744dd869dd40b6265a23fd84a402 OP_CHECKSIG

#endexercise
#markdown
# TapLeaf
* These are the leaves of the Merkle Tree
* Has a TapLeaf Version (<code>0xc0</code>) and TapScript
* Any Leaf can be executed to satisfy the Taproot Script Path
* Hash of a TapLeaf is a Tagged Hash (TapLeaf) of the version + TapScript
#endmarkdown
#code
>>> # Example of making a TapLeaf and calculating the hash
>>> from ecc import PrivateKey
>>> from hash import hash_tapleaf
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf
>>> pubkey_a = PrivateKey(11111111).point.xonly()
>>> pubkey_b = PrivateKey(22222222).point.xonly()
>>> tap_script = TapScript([pubkey_a, 0xAD, pubkey_b, 0xAC])
>>> tap_leaf = TapLeaf(tap_script)
>>> h = hash_tapleaf(int_to_byte(tap_leaf.tapleaf_version) + tap_leaf.tap_script.serialize())
>>> print(h.hex())
d1b3ee8e8c175e5db7e2ff7a87435e8f751d148b77fb1f00e14ff8ffa1c09a40

#endcode
#exercise

Calculate the TapLeaf hash whose TapScript is a 2-of-4 using pubkeys from private keys which correspond to 10101, 20202, 30303, 40404

----
>>> from ecc import PrivateKey
>>> from hash import hash_tapleaf
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create a 2-of-4 TapScript that uses OP_CHECKSIG (0xac), OP_CHECKSIGADD (0xba), OP_2 (0x52) and OP_EQUAL (0x87)
>>> tap_script = TapScript([pubkey_1, 0xAC, pubkey_2, 0xBA, pubkey_3, 0xBA, pubkey_4, 0xBA, 0x52, 0x87])  #/
>>> # create the TapLeaf with the TapScript
>>> tap_leaf = TapLeaf(tap_script)  #/
>>> # calculate the hash
>>> h = hash_tapleaf(int_to_byte(tap_leaf.tapleaf_version) + tap_leaf.tap_script.serialize())  #/
>>> # print the hash hex
>>> print(h.hex())  #/
0787f5aba506f118a90cefaf00ccfdb2785cf5998d40c3d43ebfaa5b4c6bcb7d

#endexercise
#unittest
taproot:TapRootTest:test_tapleaf_hash:
#endunittest
#markdown
# TapBranch
* These are the branches of the Merkle Tree
* These connect a left child and a right child.
* Each child is a TapLeaf or TapBranch
* Hash of a TapBranch is a Tagged Hash (TapBranch) of the left hash and right hash, sorted
#endmarkdown
#code
# Example of making a TapBranch and calculating the hash
>>> from ecc import PrivateKey
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> pubkey_1 = PrivateKey(11111111).point.xonly()
>>> pubkey_2 = PrivateKey(22222222).point.xonly()
>>> tap_script_1 = TapScript([pubkey_1, 0xAC])
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_branch = TapBranch(tap_leaf_1, tap_leaf_2)
>>> left_hash = tap_branch.left.hash()
>>> right_hash = tap_branch.right.hash()
>>> if left_hash > right_hash:
...     h = hash_tapbranch(left_hash + right_hash)
... else:
...     h = hash_tapbranch(right_hash + left_hash)
>>> print(h.hex())
60f57015577d9cc2326d980355bc0896c80a9f94dc692d8738069bc05895634c

#endcode
#exercise

TabBranch Calculation

Calculate the TabBranch hash whose left and right nodes are TapLeafs whose TapScripts are for a 1-of-2 using pubkeys from private keys which correspond to (10101, 20202) for the left, (30303, 40404) for the right

----
>>> from ecc import PrivateKey
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create two 1-of-2 TapScripts
>>> tap_script_1 = TapScript([pubkey_1, 0xAC, pubkey_2, 0xBA, 0x51, 0x87])  #/
>>> tap_script_2 = TapScript([pubkey_3, 0xAC, pubkey_4, 0xBA, 0x51, 0x87])  #/
>>> # create two TapLeafs with the TapScripts
>>> tap_leaf_1 = TapLeaf(tap_script_1)  #/
>>> tap_leaf_2 = TapLeaf(tap_script_2)  #/
>>> # create the branch
>>> tap_branch = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> # get the left and right hashes
>>> left_hash = tap_branch.left.hash()  #/
>>> right_hash = tap_branch.right.hash()  #/
>>> # calculate the hash using the sorted order with hash_tapbranch
>>> if left_hash > right_hash:  #/
...     h = hash_tapbranch(left_hash + right_hash)  #/
... else:  #/
...     h = hash_tapbranch(right_hash + left_hash)  #/
>>> # print the hex of the hash
>>> print(h.hex())  #/
f938d6fa5e3335e540f07a4007ee296640a977c89178aca79f15f2ec6acc14b6

#endexercise
#unittest
taproot:TapRootTest:test_tapbranch_hash:
#endunittest
#markdown
# Computing the Merkle Root
* The Merkle Root is the hash of the root element of the Merkle Tree
* For TapLeaf: Tagged hash (TapLeaf) of TapLeaf Version followed by the TapScript
* For TapBranch: Tagged hash (TapBranch) of the sorted children (left and right)
* It doesn't have to be the hash of anything, just has to be 32 bytes
#endmarkdown
#code
>>> # Example of Comupting the Merkle Root
>>> from ecc import PrivateKey
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> pubkey_1 = PrivateKey(11111111).point.xonly()
>>> pubkey_2 = PrivateKey(22222222).point.xonly()
>>> pubkey_3 = PrivateKey(33333333).point.xonly()
>>> tap_script_1 = TapScript([pubkey_1, 0xAC])
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_leaf_3 = TapLeaf(tap_script_3)
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)
>>> tap_root = TapBranch(tap_branch_1, tap_leaf_3)
>>> merkle_root = tap_root.hash()
>>> print(merkle_root.hex())
f53fab2e9cf0a458609226b4c42d5c0264700cdf33850c2b1423543a44ad4234

#endcode
#exercise

Calculate the External PubKey for a Taproot output whose internal pubkey is 90909 and whose Merkle Root is from two TapBranches, each of which is a single signature TapLeaf. The private keys corresponding to the left TapBranch's TapLeafs are 10101 and 20202. The private keys corresponding to the right TapBranch's TapLeafs are 30303 and 40404.

----
>>> from ecc import PrivateKey
>>> from helper import big_endian_to_int
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> internal_pubkey = PrivateKey(90909).point
>>> pubkey_1 = PrivateKey(10101).point.xonly()
>>> pubkey_2 = PrivateKey(20202).point.xonly()
>>> pubkey_3 = PrivateKey(30303).point.xonly()
>>> pubkey_4 = PrivateKey(40404).point.xonly()
>>> # create four tap scripts one for each pubkey
>>> tap_script_1 = TapScript([pubkey_1, 0xAC])  #/
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])  #/
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])  #/
>>> tap_script_4 = TapScript([pubkey_4, 0xAC])  #/
>>> # create four TapLeafs with the TapScripts
>>> tap_leaf_1 = TapLeaf(tap_script_1)  #/
>>> tap_leaf_2 = TapLeaf(tap_script_2)  #/
>>> tap_leaf_3 = TapLeaf(tap_script_3)  #/
>>> tap_leaf_4 = TapLeaf(tap_script_4)  #/
>>> # create two TapBranches that have these TapLeafs
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> tap_branch_2 = TapBranch(tap_leaf_3, tap_leaf_4)  #/
>>> # create another TapBranch that corresponds to the merkle root and get its hash
>>> merkle_root = TapBranch(tap_branch_1, tap_branch_2).hash()  #/
>>> # the external public key is the internal public key tweaked with the Merkle Root
>>> external_pubkey = internal_pubkey.tweaked_key(merkle_root)  #/
>>> # print the hex of the xonly of the external pubkey
>>> print(external_pubkey.xonly().hex())  #/
8b9f09cd4a33e62b0c9d086056bbdeb7a218c1e4830291b9be56841b31d94ccb

#endexercise
#markdown
# Control Block
* Required for spending a TapScript, last element of Witness
* TapScript Version (<code>0xc0</code> or <code>0xc1</code>)
* The last bit expresses the parity of the external pubkey, which is necessary for batch verification
* Internal PubKey $P$
* Merkle Proof (list of hashes to combine to get to the Merkle Root)
#endmarkdown
#markdown
# Merkle Proof
* List of hashes
* Combine each with the hash of the TapScript, sorting them each time
* The result is the Merkle Root, which can be combined with the Internal PubKey $P$ to get the tweak $t$
* If the result of $P+tG=Q$ where $Q$ is the External PubKey from the UTXO, this is a valid TapScript
#endmarkdown
#code
>>> # Example of Control Block Validation
>>> from ecc import PrivateKey, S256Point
>>> from hash import hash_tapbranch
>>> from helper import int_to_byte
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> external_pubkey_xonly = bytes.fromhex("cbe433288ae1eede1f24818f08046d4e647fef808cfbbffc7d10f24a698eecfd")
>>> pubkey_2 = bytes.fromhex("027aa71d9cdb31cd8fe037a6f441e624fe478a2deece7affa840312b14e971a4")
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_leaf_1_hash = bytes.fromhex("76f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dff")
>>> tap_leaf_3_hash = bytes.fromhex("5dd270ec91aa5644d907059400edfd98e307a6f1c6fe3a2d1d4550674ff6bc6e")
>>> internal_pubkey = S256Point.parse(bytes.fromhex("407910a4cfa5fe195ad4844b6069489fcb429f27dff811c65e99f7d776e943e5"))
>>> current = tap_leaf_2.hash()
>>> for h in (tap_leaf_1_hash, tap_leaf_3_hash):
...     if h < current:
...         current = hash_tapbranch(h + current)
...     else:
...         current = hash_tapbranch(current + h)
>>> print(internal_pubkey.tweaked_key(current).xonly() == external_pubkey_xonly)
True

>>> print(internal_pubkey.p2tr_address(current, network="signet"))
tb1pe0jrx2y2u8hdu8eysx8ssprdfej8lmuq3namllrazrey56vwan7s5j2wr8

#endcode
#exercise

Validate the Control Block for the pubkey whose private key is 40404 for the previous external pubkey

----
>>> from ecc import PrivateKey, S256Point
>>> from helper import big_endian_to_int
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> external_pubkey_xonly = bytes.fromhex("8b9f09cd4a33e62b0c9d086056bbdeb7a218c1e4830291b9be56841b31d94ccb")
>>> internal_pubkey = PrivateKey(90909).point
>>> hash_1 = bytes.fromhex("22cac0b60bc7344152a8736425efd62532ee4d83e3de473ed82a64383b4e1208")
>>> hash_2 = bytes.fromhex("a41d343d7419b99bfe8e66752fc3c45fd14aa2cc5ef5bf9073ed28dfc60e2e34")
>>> pubkey_4 = bytes.fromhex("9e5f5a5c29d33c32185a3dc0a9ccb3e72743744dd869dd40b6265a23fd84a402")
>>> # create the TapScript and TapLeaf for pubkey 4
>>> tap_script_4 = TapScript([pubkey_4, 0xAC])  #/
>>> tap_leaf_4 = TapLeaf(tap_script_4)  #/
>>> # set the current hash to the TapLeaf's hash
>>> current = tap_leaf_4.hash()  #/
>>> # loop through hash_1 and hash_2
>>> for h in (hash_1, hash_2):  #/
...     # do a hash_tapbranch of h and current, sorted alphabetically
...     if h < current:  #/
...         current = hash_tapbranch(h + current)  #/
...     else:  #/
...         current = hash_tapbranch(current + h)  #/
>>> # get the external pubkey using the current hash as the merkle root with the internal pubkey
>>> external_pubkey = internal_pubkey.tweaked_key(current)  #/
>>> # check to see if the external pubkey's xonly is correct
>>> print(external_pubkey.xonly() == external_pubkey_xonly)  #/
True

#endexercise
#unittest
taproot:TapRootTest:test_control_block:
#endunittest
#exercise

Create a Signet P2TR address with these Script Spend conditions:

1. Internal Public Key is <code>cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e</code>
2. Leaf 1 and Leaf 2 make Branch 1, Branch 1 and Leaf 3 make Branch 2, which is the Merkle Root
3. All TapLeaf are single key locked TapScripts (pubkey, OP_CHECKSIG)
4. Leaf 1 uses your xonly pubkey
5. Leaf 2 uses this xonly pubkey: <code>331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec</code>
6. Leaf 3 uses this xonly pubkey: <code>158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f</code>

----
>>> from ecc import PrivateKey, S256Point
>>> from helper import sha256, big_endian_to_int
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_secret = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> internal_pubkey = S256Point.parse(bytes.fromhex("cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e"))
>>> pubkey_2 = bytes.fromhex("331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec")
>>> pubkey_3 = bytes.fromhex("158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f")
>>> # get your xonly pubkey
>>> my_xonly = PrivateKey(my_secret).point.xonly()  #/
>>> # make the first TapScript and TapLeaf using your xonly and OP_CHECKSIG (0xAC)
>>> tap_script_1 = TapScript([my_xonly, 0xAC])  #/
>>> tap_leaf_1 = TapLeaf(tap_script_1)  #/
>>> # make the second and third TapLeaves using pubkey_2 and pubkey_3 respectively
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])  #/
>>> tap_leaf_2 = TapLeaf(tap_script_2)  #/
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])  #/
>>> tap_leaf_3 = TapLeaf(tap_script_3)  #/
>>> # make a TapBranch with leaf 1 and 2
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> # make a TapBranch with branch 1 and leaf 3
>>> tap_branch_2 = TapBranch(tap_branch_1, tap_leaf_3)  #/
>>> # get the hash of this branch, this is the Merkle Root
>>> merkle_root = tap_branch_2.hash()  #/
>>> # print the address using the p2tr_address method of internal_pubkey and specify signet
>>> print(internal_pubkey.p2tr_address(merkle_root, network="signet"))  #/
tb1pxh7kypwsvxnat0z6588pufhx43r2fnqjyn846qj5kx8mgqcamvjsyn5cjg

#endexercise
#exercise

Send yourself the rest of the coins from the output of the previous exercise to the address you just created

Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction

----
>>> from ecc import PrivateKey, S256Point
>>> from helper import sha256, big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> from tx import Tx, TxIn, TxOut
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_secret = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> my_private_key = PrivateKey(my_secret)
>>> prev_tx = bytes.fromhex("69804495c439176266c473081e2f9a3cd298e60a17c8b035fd3070073b865a9c")  #/prev_tx = bytes.fromhex("<fill this in with the tx where you spent last time>")
>>> prev_index = 1
>>> target_address = "tb1pxh7kypwsvxnat0z6588pufhx43r2fnqjyn846qj5kx8mgqcamvjsyn5cjg"  #/target_address = "<fill this in with the address from the last exercise>"
>>> fee = 500
>>> # create a transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the target amount
>>> target_amount = tx_in.value(network="signet") - fee
>>> target_script = address_to_script_pubkey(target_address)
>>> # create a transaction output
>>> tx_out = TxOut(target_amount, target_script)  #/
>>> # create a transaction, segwit=True and network="signet"
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)  #/
>>> # calculate the tweaked key from your private key
>>> signing_key = my_private_key.tweaked_key()  #/
>>> # sign the transaction using sign_p2tr_keypath
>>> tx_obj.sign_p2tr_keypath(0, signing_key)  #/
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())
010000000001019c5a863b077030fd35b0c8170ae698d23c9a2f1e0873c466621739c4954480690100000000ffffffff0178e600000000000022512035fd6205d061a7d5bc5aa1ce1e26e6ac46a4cc1224cf5d0254b18fb4031ddb250140b33905727e316ab7fc8c2816761d61af9f1c535cee632a210642f07d619af632c6df51d63099be31e6d12ecd2a465543861eab6e53feb09ccd49288bda1cb8f600000000

#endexercise
#exercise

Now spend this output using the script path from the second TapLeaf send it all to <code>tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg</code>

Use <a href="https://mempool.space/signet/tx/push to broadcast your transaction" target="_mempool">Mempool Signet</a> to broadcast your transaction

----
>>> from ecc import PrivateKey, S256Point
>>> from helper import sha256, big_endian_to_int
>>> from script import address_to_script_pubkey
>>> from taproot import TapScript, TapLeaf, TapBranch
>>> from tx import Tx, TxIn, TxOut
>>> from witness import Witness
>>> my_email = b"jimmy@programmingblockchain.com"  #/my_email = b"<fill this in with your email>"
>>> my_secret = big_endian_to_int(sha256(my_email))
>>> my_private_key = PrivateKey(my_secret)
>>> internal_pubkey = S256Point.parse(bytes.fromhex("cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e"))
>>> pubkey_2 = bytes.fromhex("331a8f6a14e1b41a6b523ddb505fbc0662a6446bd42408692497297d3474aeec")
>>> pubkey_3 = bytes.fromhex("158a49d62c384c539a453e41a70214cfb85184954ae5c8df4b47eb74d58ff16f")
>>> my_xonly = my_private_key.point.xonly()
>>> tap_script_1 = TapScript([my_xonly, 0xAC])
>>> tap_leaf_1 = TapLeaf(tap_script_1)
>>> tap_script_2 = TapScript([pubkey_2, 0xAC])
>>> tap_leaf_2 = TapLeaf(tap_script_2)
>>> tap_script_3 = TapScript([pubkey_3, 0xAC])
>>> tap_leaf_3 = TapLeaf(tap_script_3)
>>> prev_tx = bytes.fromhex("201409034581136743bd7fd0a63f659d8142f1a41031d5a3c96bbe72135ab8a2")  #/prev_tx = bytes.fromhex("<fill this in with the tx you just submitted>")
>>> prev_index = 0
>>> target_address = "tb1q7kn55vf3mmd40gyj46r245lw87dc6us5n50lrg"
>>> fee = 500
>>> # create the two branches needed (leaf 1, leaf 2), (branch 1, leaf 3)
>>> tap_branch_1 = TapBranch(tap_leaf_1, tap_leaf_2)  #/
>>> tap_branch_2 = TapBranch(tap_branch_1, tap_leaf_3)  #/
>>> # create a transaction input
>>> tx_in = TxIn(prev_tx, prev_index)  #/
>>> # calculate the target amount
>>> target_amount = tx_in.value(network="signet") - fee
>>> # calculate the target script
>>> target_script = address_to_script_pubkey(target_address)
>>> # create a transaction output
>>> tx_out = TxOut(target_amount, target_script)  #/
>>> # create a transaction, segwit=True and network="signet"
>>> tx_obj = Tx(1, [tx_in], [tx_out], network="signet", segwit=True)  #/
>>> # create the control block with variables left over from the exercise 2 times ago
>>> cb = tap_branch_2.control_block(internal_pubkey, tap_leaf_1)
>>> tx_in.witness = Witness([tap_script_1.raw_serialize(), cb.serialize()])
>>> msg = tx_obj.sig_hash(0)
>>> sig = my_private_key.sign_schnorr(msg).serialize()
>>> tx_in.witness.items.insert(0, sig)
>>> print(tx_obj.verify())
True
>>> # print the serialized hex
>>> print(tx_obj.serialize().hex())
01000000000101a2b85a1372be6bc9a3d53110a4f142819d653fa6d07fbd4367138145030914200000000000ffffffff0184e4000000000000160014f5a74a3131dedb57a092ae86aad3ee3f9b8d721403403b1681a67f40e6767b2db64744ad3f005d3971645135d58a3e1826d5c960bc281ce187bc9270c51ed7833fcf5e8415501862d51b0ebd051917d9878104778f292220cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9eac61c0cd04c1bf88ca891af152fc57c36523ab59efb16b7ec07caca0cfc4a1f2051d9e76f5c1cdfc8b07dc8edca5bef2b4991201c5a0e18b1dbbcfe00ef2295b8f6dffaf5548715217f7a892c7c5ff787a97b6e2f123287a1a354fe3ccda09c39d5d7300000000

#endexercise
"""

FUNCTIONS = """
hash.tagged_hash
ecc.S256Point.xonly
ecc.S256Point.verify_schnorr
ecc.PrivateKey.sign_schnorr
ecc.S256Point.tweak
ecc.S256Point.tweaked_key
ecc.S256Point.p2tr_script
ecc.PrivateKey.tweaked_key
op.op_checksigadd_schnorr
taproot.TapLeaf.hash
taproot.TapBranch.hash
taproot.ControlBlock.merkle_root
taproot.ControlBlock.external_pubkey
"""
