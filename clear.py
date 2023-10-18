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


def chop_word(s):
    for i, _ in enumerate(s):
        letter = s[i:i+1]
        if letter not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_":
            return s[:i]

raw_items_2 = """hash.tagged_hash
op.op_checksigadd_schnorr
"""

to_clear = {}
files = {}
for item in raw_items_2.split():
    components = item.split('.')
    files[components[0]] = 1
    to_clear[item] = 1

for filename in files.keys():
    modified_file = ""
    with open(f"session/{filename}.py", "r") as file:
        current_func = None
        active = False
        for line in file:
            if line == "\n":
                if active:
                    modified_file += "    raise NotImplementedError\n"
                    active = False
                if current_func:
                    current_func = None
            if active:
                if line.lstrip().startswith("#") or line.lstrip().startswith("\"\"\""):
                    modified_file += line
            else:
                modified_file += line
            if line.startswith("def "):
                current_func = chop_word(line.lstrip()[4:])
                key = f"{filename}.{current_func}"
                if to_clear.get(key):
                    active = True
    with open(f"session/{filename}.py", "w") as file:
        file.write(modified_file)

to_clear = {}
files = {}
for item in raw_items.split():
    components = item.split('.')
    files[components[0]] = 1
    to_clear[item] = 1

for filename in files.keys():
    modified_file = ""
    with open(f"session/{filename}.py", "r") as file:
        current_class = None
        current_func = None
        active = False
        for line in file:
            if line == "\n":
                if active:
                    modified_file += "        raise NotImplementedError\n"
                    active = False
                if current_func:
                    current_func = None
                elif current_class:
                    current_class = None
            if active:
                if line.lstrip().startswith("#") or line.lstrip().startswith("\"\"\""):
                    modified_file += line
            else:
                modified_file += line
            if line.startswith("class "):
                current_class = chop_word(line[6:])
            if line.startswith("    def "):
                current_func = chop_word(line.lstrip()[4:])
                key = f"{filename}.{current_class}.{current_func}"
                if to_clear.get(key):
                    active = True
    with open(f"session/{filename}.py", "w") as file:
        file.write(modified_file)
