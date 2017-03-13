import os
import sys


from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, ZmqEndpointType

# Dont know what this does
#rootdir = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), '..'))
#sys.path.append(rootdir)
#os.chdir(rootdir)


class Broadcast():

    def __init__(self, miner):
        self.factory = ZmqFactory()
        self.publish_endpoint = ZmqEndpoint(ZmqEndpointType.bind, "tcp://127.0.0.1:5610")
        self.subscribe_endpoint = ZmqEndpoint(ZmqEndpointType.connect, "tcp://127.0.0.1:5610")
        self.publisher = ZmqPubConnection(self.factory, self.publish_endpoint)
        self.subscriber = BroadcastSubscriber(self.factory, self.subscribe_endpoint, miner)
        self.subscriber.subscribe(b"propose")
        self.subscriber.subscribe(b"commit")
        self.subscriber.subscribe(b"reinforce")
        print("init completed")

    def broadcast(self, data, tag):
        print("broadcasting: ")
        self.publisher.publish(data.encode('UTF-8'), tag.encode('UTF-8'))


class BroadcastSubscriber(ZmqSubConnection):

    def __init__(self, factory, subscribe_endpoint, miner):
        ZmqSubConnection.__init__(self, factory, subscribe_endpoint)
        self.miner = miner

    def gotMessage(self, message, tag):
        print("GOT IT")

        # OPTION 1
        # from Miner import Miner
        # self.miner.processMessage(message.decode(), tag.decode())

        # OPTION 2
        from Miner import Miner
        if tag.decode() == "propose":
            self.miner.processProposal(message.decode())
        elif tag.decode() == "commit":
            self.miner.processCommit(message.decode())
        elif tag.decode() == "reinforce":
            self.miner.processReinforcement(message.decode())

# TODO: idea: have a TAG to different events
