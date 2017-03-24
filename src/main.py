from twisted.internet import task, reactor
import argparse
from miner import Miner

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="the miner's id", type=int)
    args = parser.parse_args()
    miner = Miner(args.id)
    task.deferLater(reactor, 1, miner.run)
    reactor.run()



