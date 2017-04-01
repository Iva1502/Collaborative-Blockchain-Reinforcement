from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqEndpointType
import argparse
from time import sleep
import json


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
        tag = "transaction"
        print("broadcasting: ")
        self.publisher.publish(data.encode(), tag.encode())

    # We assume the config file is well formed
    # Read the port corresponding to its id from the configuration port
    def __get_port(self):
        publish_port = None
        file = open('../conf/miner_discovery.json')
        data = json.load(file)
        for client in data['clients']:
            port = client['port']
            if client['id'] == self.identity:
                publish_port = port
                break
        if publish_port is None:
            raise Exception("No publish port for miner with id: " + str(self.identity))
        return publish_port


def main(identity):
    client = Client(identity)
    nonce = -1
    while True:
        nonce += 1
        sleep(3)
        client.broadcast("Alice buys a watch from Bob for " + str(nonce) + " chf")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("id", help="the client's id", type=int)
    args = parser.parse_args()
    main(args.id)
