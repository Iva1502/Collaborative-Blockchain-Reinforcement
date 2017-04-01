import hashlib

# FIXME see if an attribute would work or if we need an object Stop
class Hash():

    def __init__(self, miner):
        self.miner = miner

    def mine(self, block, stop):
        hash_block = block.hash(hex=False)
        # 59 Fs
        threshold = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        nonce = -1
        while not stop.stop:
            # increment the nonce
            nonce += 1
            # create an hash function object
            hash_function = hashlib.sha256()
            # feed it with the block, the ID and the nonce
            hash_function.update(hash_block)
            #Do we need it?
            hash_function.update(self.miner.id.to_bytes(16, byteorder='big'))
            hash_function.update(nonce.to_bytes(16, byteorder='big'))
            # compute the hash
            hash_value = hash_function.hexdigest()
            if int(hash_value, 16) < threshold:
                # inform the miner that an hash lower than the threshold was found
                from twisted.internet import reactor
                reactor.callFromThread(self.miner.new_hash_found, hash_value, nonce)


