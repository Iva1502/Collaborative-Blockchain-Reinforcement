from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, ZmqEndpointType
import sys
import xml.etree.ElementTree as ET


class Broadcast():

    def __init__(self, miner):
        # read the publish and subscribe ports from the configuration file
        publish_port, subscribe_ports = self.__get_ports(miner.id)
        # create a factory
        self.factory = ZmqFactory()
        # create a connection to publish
        publish_endpoint = ZmqEndpoint(ZmqEndpointType.bind, "tcp://127.0.0.1:" + publish_port)
        self.publisher = ZmqPubConnection(self.factory, publish_endpoint)
        # create connections to subscribe
        self.subscribers = []
        for subscribe_port in subscribe_ports:
            subscribe_endpoint = ZmqEndpoint(ZmqEndpointType.connect, "tcp://127.0.0.1:" + subscribe_port)
            subscriber = BroadcastSubscriber(self.factory, subscribe_endpoint, miner)
            self.subscribers.append(subscriber)
            # subcribe to the types of events
            subscriber.subscribe(b"propose")
            subscriber.subscribe(b"commit")
            subscriber.subscribe(b"reinforce")

    def broadcast(self, data, tag):
        print("broadcasting: ")
        self.publisher.publish(data.encode('UTF-8'), tag.encode('UTF-8'))


    # FIXME should I see if the configuration file has twice the same ID?
    def __get_ports(self, identity):
        subscribe_ports = []
        publish_port = None
        tree = ET.parse('../conf/miner_discovery.xml')
        root = tree.getroot()
        for miner in root.findall('miner'):
            identifier = miner.get('id')
            port = miner.find('port').text
            if str(identity) == identifier:
                publish_port = port
            subscribe_ports.append(port)
        if publish_port is None:
            # FIXME what is more correct here?
            print("The ID is not in the configuration file")
            sys.exit(-1)
        return publish_port, subscribe_ports


class BroadcastSubscriber(ZmqSubConnection):

    def __init__(self, factory, subscribe_endpoint, miner):
        ZmqSubConnection.__init__(self, factory, subscribe_endpoint)
        self.miner = miner

    def gotMessage(self, message, tag):
        # OPTION 1
        # from Miner import Miner
        # self.miner.processMessage(message.decode(), tag.decode())

        # OPTION 2
        if tag.decode() == "propose":
            self.miner.processProposal(message.decode())
        elif tag.decode() == "commit":
            self.miner.processCommit(message.decode())
        elif tag.decode() == "reinforce":
            self.miner.processReinforcement(message.decode())
