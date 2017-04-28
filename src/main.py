from twisted.internet import task, reactor
import argparse
import signal
import sys
from Crypto.PublicKey import RSA

from miner import Miner


def shutdown():
    print("*******")
    print("STOP!!!")
    print("*******")
    miner.stop()
    reactor.stop()


def signal_handler(signum, frame):
    reactor.callFromThread(shutdown)


def install_handlers():
    signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="the miner's id", type=int)
    parser.add_argument("-f", "--faulty",
                        help="the miner sends all the reinforcements collected so far to all the proposals",
                        action="store_true")
    args = parser.parse_args()
    args = parser.parse_args()
    miner = Miner(args.id, args.faulty)
    install_handlers()
    task.deferLater(reactor, 1, miner.run)
    reactor.run()
