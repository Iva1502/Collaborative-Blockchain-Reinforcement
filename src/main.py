from twisted.internet import task, reactor
from miner import Miner

if __name__ == '__main__':
    miner = Miner()
    task.deferLater(reactor, 1, miner.run)
    reactor.run()
