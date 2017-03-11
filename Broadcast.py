#!env/bin/python

import os
import sys


from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, ZmqEndpointType

# Dont know what this does
#rootdir = os.path.realpath(os.path.join(os.path.dirname(sys.argv[0]), '..'))
#sys.path.append(rootdir)
#os.chdir(rootdir)


class Broadcast():

    def __init__(self):
        self.factory = ZmqFactory()
        self.publish_endpoint = ZmqEndpoint(ZmqEndpointType.bind, "tcp://127.0.0.1:5603")
        self.subscribe_endpoint = ZmqEndpoint(ZmqEndpointType.connect, "tcp://127.0.0.1:5603")
        self.publisher = ZmqPubConnection(self.factory, self.publish_endpoint)
        self.subscriber = BroadcastSubscriber(self.factory, self.subscribe_endpoint)
        self.subscriber.subscribe(b"")
        print("init completed")

    def broadcast(self, data):
        print("broadcasting: ")
        self.publisher.publish(data.encode('UTF-8'))


class BroadcastSubscriber(ZmqSubConnection):

    def __init__(self, factory, subscribe_endpoint):
        ZmqSubConnection.__init__(self, factory, subscribe_endpoint)

    def gotMessage(self, message, tag):
        print(message.decode())
        print("GOT IT")
        from twisted.internet import reactor
        reactor.stop()
        # FIXME how can I create an event in Miner.processMessage ?

# TODO: idea: have a TAG to different events
