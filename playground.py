from Miner import Miner

miner = Miner()

from twisted.internet import reactor
reactor.callLater(1, miner.startHashing, "this is the block")
reactor.run()
