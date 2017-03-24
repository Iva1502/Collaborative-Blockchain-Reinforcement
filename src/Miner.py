from twisted.internet import task, reactor
from blockchain import Blockchain
from hash import Hash
from states import Mining
from broadcast import Broadcast

class Stop:
    def __init__(self):
        self.stop = False

    def setStop(self):
        self.stop = True

class Miner:
    def __init__(self):
        self.broadcast = Broadcast()
        self.blockchain = Blockchain()
        self.current_block = None
        self.hash = Hash()
        self.state = Mining(self)
        self.stop_mining = None
        self.nonce_list = []

    def run(self):
        print("Miner was run")
        self.start_new_mining()

    def start_new_mining(self):
        self.current_block = self.blockchain.get_last()
        self.stop_mining = Stop()
        reactor.callInThread(self.hash.run, self.current_block[1], self.stop_mining)

    def hash_value(self, val, nonce):
        self.state.hash_value_process(val, nonce)

    def message(self, type, value):
        self.state.message_process(type, value)