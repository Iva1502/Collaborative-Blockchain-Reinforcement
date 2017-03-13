from Broadcast import Broadcast


class Miner():

    def __init__(self):
        self.broadcast = Broadcast(self)

    def broadcastMessage(self, data, tag):
        self.broadcast.broadcast(data, tag)

    def processMessage(self, message, tag):
        print("I already have the " + message)
        print("And the tag " + tag)
        from twisted.internet import reactor
        reactor.stop()

    def processProposal(self, message):
        print("I received the proposal " + message)
        from twisted.internet import reactor
        reactor.stop()

    def processCommit(self, message):
        print("I received the commit " + message)
        from twisted.internet import reactor
        reactor.stop()

    def processReinforcement(self, message):
        print("I received the reinforcement " + message)
        from twisted.internet import reactor
        reactor.stop()

