from shutil import copy

raw_items = """ecc.S256Point.xonly
ecc.S256Point.verify_schnorr
ecc.PrivateKey.sign_schnorr
ecc.S256Point.tweak
ecc.S256Point.tweaked_key
ecc.S256Point.p2tr_script
ecc.PrivateKey.tweaked_key
taproot.TapLeaf.hash
taproot.TapBranch.hash
taproot.ControlBlock.merkle_root
taproot.ControlBlock.external_pubkey
"""

raw_items_2 = """hash.tagged_hash
op.op_checksigadd_schnorr
"""

files = {}

for item in raw_items.split():
    components = item.split('.')
    files[components[0]] = 1

for item in raw_items_2.split():
    components = item.split('.')
    files[components[0]] = 1

for filename in files.keys():
    copy(f"session/complete/{filename}.py", f"session/{filename}.py")
