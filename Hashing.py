# import hashlib
import random


# the block should come in hexa
def mine(block):
    rand = 1
    while rand >= 1e-6:
        rand = random.random()
        print(rand)
    return rand

print(mine("ABCD"))


# bytes_block = block.encode()
# threshold = 0
# hash_int = int("F" * 64, 16)
# nonce = 0
# while hash_int > int("F" * 56, 16):
#     print("{0:08x}".format(nonce))
#     hash_function = hashlib.sha256()
#     hash_function.update(bytes_block)
#     hash_function.update(nonce.to_bytes(8, byteorder='big'))
#     hash = hash_function.digest()
#     hash_int = int.from_bytes(hash, byteorder='big')
#     nonce += 1