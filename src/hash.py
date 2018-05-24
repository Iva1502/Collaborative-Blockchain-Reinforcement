import hashlib
from constants import REINF_TH
import time
import datetime as dt
from threading import Thread
from twisted.internet import reactor
from twisted.internet import task
from twisted.internet import threads
import logging

#hash_block is the hash of the block on top of which the current mining is going
def compute_hash(hash_block, nonce, pub_key):
    # create an hash function object
    hash_function = hashlib.sha256()
    # feed it with the block, the ID and the nonce
    hash_function.update(hash_block)
    hash_function.update(pub_key)
    hash_function.update(nonce.to_bytes(16, byteorder='big'))
    # compute the hash
    return hash_function.hexdigest()

#checks if the produced hash is less than the given mining difficulty parameter
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
            time.sleep(0.015)
            self.miner.counter += 1
            hash_value = compute_hash(hash_block, nonce, self.miner.public_key.exportKey('DER'))
            #print(int(hash_value,16))
            if int(hash_value, 16) < REINF_TH:
                logging.info("RF found but not transmitted")
                # inform the miner that an hash lower than the threshold was found
                from twisted.internet import reactor
                reactor.suggestThreadPoolSize(40)
                reactor.callFromThread(self.miner.new_hash_found, hash_value, nonce)


        '''
        def runEverySecond():
            nonce += 1
            hash_value = compute_hash(hash_block, nonce, self.miner.public_key.exportKey('DER'))
            if (int(hash_value, 16) < REINF_TH):
            # inform the miner that a hash lower than the threshold was found
            reactor.callFromThread(self.miner.new_hash_found, hash_value, nonce)


        h = task.LoopingCall(reactor, 1, compute_hash, hash_block, nonce,
                                         self.miner.public_key.exportKey('DER'))
        h.start(1.0)
            #hash_value = reactor.callLater(1, compute_hash, hash_block, nonce, self.miner.public_key.exportKey('DER'))

            #print(hash_value)
            #if (hash_value is not None):
                #if (int(hash_value, 16) < REINF_TH):

                    # inform the miner that a hash lower than the threshold was found
                    #reactor.callFromThread(self.miner.new_hash_found, hash_value, nonce)
                    #invokes the method new_hash_found in miner.py with the 2 arguments
                    #giving a function to the reactor to execute within its own thread
'''



