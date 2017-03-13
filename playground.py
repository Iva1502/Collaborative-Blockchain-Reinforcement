from Miner import Miner

miner = Miner()

from twisted.internet import reactor
reactor.callLater(1, miner.broadcastMessage, "this is a commit", "commit")
reactor.run()
