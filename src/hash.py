import hashlib
from constants import REINF_TH


def compute_hash(hash_block, nonce, pub_key):
    # create an hash function object
    hash_function = hashlib.sha256()
    # feed it with the block, the ID and the nonce
    hash_function.update(hash_block)
    hash_function.update(pub_key)
    hash_function.update(nonce.to_bytes(16, byteorder='big'))
    # compute the hash
    return hash_function.hexdigest()


def check_hash(block, nonce, pub_key, th):
    return int(compute_hash(block.hash(hex=False), nonce, pub_key.exportKey('DER')), 16) < th


class Hash():
    def __init__(self, miner):
        self.miner = miner

    def mine(self, block, stop):
        hash_block = block.hash(hex=False)
        nonce = -1
        while not stop.stop:
            # increment the nonce
            nonce += 1
            hash_value = compute_hash(hash_block, nonce, self.miner.public_key.exportKey('DER'))
            if int(hash_value, 16) < REINF_TH:
                # inform the miner that an hash lower than the threshold was found
                from twisted.internet import reactor
                reactor.callFromThread(self.miner.new_hash_found, hash_value, nonce)


