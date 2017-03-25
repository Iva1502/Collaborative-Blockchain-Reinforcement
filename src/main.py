from twisted.internet import task, reactor
import argparse
import signal
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
    args = parser.parse_args()
    miner = Miner(args.id)
    install_handlers()
    task.deferLater(reactor, 1, miner.run)
    reactor.run()


