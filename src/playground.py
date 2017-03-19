from Miner import Miner
import sys, argparse


def main(identity):
    miner = Miner(identity)
    from twisted.internet import reactor
    reactor.callLater(1, miner.broadcastMessage, "cenas", "reinforce")
    reactor.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="the miner's id", type=int)
    args = parser.parse_args()
    main(args.id)
