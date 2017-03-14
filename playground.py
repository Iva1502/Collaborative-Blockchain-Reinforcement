from Miner import Miner
import sys, getopt

# creates a Miner process that broadcasts a message and subscribes miners in the configuration file

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"hi:m:",["id=", "message="])
    except getopt.GetoptError:
        print ('test.py -i <id> -m <message>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('test.py -i <id> -m <message>')
            sys.exit()
        elif opt in ("-i", "--id"):
            identifier = arg
        elif opt in ("-m", "--message"):
            message = arg

    miner = Miner(int(identifier, 10))
    from twisted.internet import reactor
    reactor.callLater(10, miner.broadcastMessage, message, "propose")
    reactor.callLater(30, reactor.stop)
    reactor.run()


if __name__ == "__main__":
   main(sys.argv[1:])
