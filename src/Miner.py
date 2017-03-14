from Broadcast import Broadcast
from Hash import Hash

class Miner():

    def __init__(self, id):
        self.id = id
        self.broadcast = Broadcast(self)
        self.hash = Hash(self)

    def broadcastMessage(self, data, tag):
        self.broadcast.broadcast(data, tag)

    def processMessage(self, message, tag):
        print("I already have the " + message)
        print("And the tag " + tag)

    def processProposal(self, message):
        print("I am " + str(self.id) + " and received the proposal " + message)

    def processCommit(self, message):
        print("I received the commit " + message)

    def processReinforcement(self, message):
        print("I received the reinforcement " + message)

    def startHashing(self, block):
        self.hash.mine(block)

    def newHashFound(self, hash_value, nonce):
        print("I GOT THE NEW HASH " + hash_value + "  " + str(nonce))

