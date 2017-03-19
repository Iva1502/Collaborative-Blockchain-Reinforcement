from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqEndpointType
import sys
import argparse
import random
import xml.etree.ElementTree as ET


class Client():
    def __init__(self, identity):
        self.identity = identity
        # read the publish from the configuration file
        publish_port = self.__get_port()
        print("I am at the publish port:")
        print(publish_port)
        # create a factory
        self.factory = ZmqFactory()
        # create a connection to publish
        publish_endpoint = ZmqEndpoint(ZmqEndpointType.bind, "tcp://127.0.0.1:" + publish_port)
        self.publisher = ZmqPubConnection(self.factory, publish_endpoint)

    def broadcast(self, data):
        tag = "reinforce"
        print("broadcasting: ")
        self.publisher.publish(data.encode('UTF-8'), tag.encode('UTF-8'))

    # We assume the config file is well formed
    # Read the port corresponding to its id from the configuration port
    def __get_port(self):
        publish_port = None
        tree = ET.parse('../conf/miner_discovery.xml')
        root = tree.getroot()
        clients = root.find('clients')
        for client in clients:
            identifier = client.get('id')
            port = client.find('port').text
            if str(self.identity) == identifier:
                publish_port = port
                break
        if publish_port is None:
            # FIXME what is more correct here?
            print("The ID is not in the configuration file")
            sys.exit(-1)
        return publish_port


def main(identity):
    client = Client(identity)
    nonce = -1
    while True:
        nonce += 1
        rand = random.randint(1, 100000)
        if rand == 894:
            client.broadcast("Alice buys a watch to Bob for " + str(nonce) + " chf")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="the client's id", type=int)
    args = parser.parse_args()
    main(args.id)
