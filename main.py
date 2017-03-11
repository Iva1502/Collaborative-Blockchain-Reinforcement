from Broadcast import Broadcast


class Miner():

    def __init__(self):
        self.broadcast = Broadcast()

    def broadcastMessage(self, data):
        self.broadcast.broadcast(data)

    def processMessage(self, message):
        print("I already have the " + message)

miner = Miner()

from twisted.internet import reactor
reactor.callLater(1, miner.broadcastMessage, "food")
reactor.run()


