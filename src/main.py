from twisted.internet import task, reactor
import argparse
import signal
import logging
from miner import Miner


def shutdown():
    print("*******")
    print("STOP!!!")
    print("*******")
    miner.stop()
    reactor.stop()


def signal_handler(signum, frame):
    reactor.suggestThreadPoolSize(40)
    reactor.callFromThread(shutdown)


def install_handlers():
    signal.signal(signal.SIGINT, signal_handler)
    #Sets handlers for asynchronous events

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="the miner's id", type=int)
    parser.add_argument("-f", "--faulty",
                        help="the miner sends all the reinforcements collected so far to all the proposals",
                        action="store_true")
    args = parser.parse_args()
    filename = "../log/miner" + str(args.id) + ".log"
    logging.basicConfig(filename=filename, format='%(asctime)s %(message)s', level=logging.INFO)
    logging.info("---------------------------------------------------------")
    miner = Miner(args.id, args.faulty)
    install_handlers()
    # IN: task is part of the twisted package and deferLater method schedules tasks for the future,
    # it conveniently takes care of creating a Deferred and setting up a delayed call
    task.deferLater(reactor, 1, miner.run)
    reactor.suggestThreadPoolSize(40)
    reactor.run()
    #All callbacks registered with the reactor (ex. dataReceived, connectionLost..) are called from reactor.run
    # and these callbacks are run in the “main thread”, or “reactor thread”
