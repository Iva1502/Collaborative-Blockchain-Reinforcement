import hashlib
from time import sleep

class Hash():

    def __init__(self, miner):
        self.miner = miner


    def mine(self, block):
        bytes_block = block.encode()
        # 60 Fs
        threshold = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        nonce = -1
        while True:
            # increment the nonce
            nonce += 1
            # create an hash function object
            hash_function = hashlib.sha256()
            # feed it with the block and the nonce
            hash_function.update(bytes_block)
            hash_function.update(nonce.to_bytes(16, byteorder='big'))
            # compute the hash
            hash_value = hash_function.hexdigest()
            if int(hash_value, 16) < threshold:
                # inform the miner that an hash lower than the threshold was found
                from twisted.internet import reactor
                from Miner import Miner
                reactor.callWhenRunning(self.miner.newHashFound, hash_value, nonce)

