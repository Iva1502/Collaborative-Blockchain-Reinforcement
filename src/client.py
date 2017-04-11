from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqEndpointType
import argparse
from time import sleep
import json
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


class Client():
    def __init__(self, identity):
        self.identity = identity
        # read the publish from the configuration file
        publish_port, self.pub_key = self.__read_conf()
        print("I am at the publish port:")
        print(publish_port)
        # create a factory
        self.factory = ZmqFactory()
        # create a connection to publish
        publish_endpoint = ZmqEndpoint(ZmqEndpointType.bind, "tcp://127.0.0.1:" + publish_port)
        self.publisher = ZmqPubConnection(self.factory, publish_endpoint)

    def broadcast(self, data):
        tag = "transaction"
        transaction = Transaction(data, self.pub_key)
        signed_data = self.sign(transaction.get_json())
        self.publisher.publish(signed_data, tag.encode())

    def sign(self, data):
        filename = "../keys/clients/client"+str(self.identity)+".key"
        key = RSA.importKey(open(filename).read())
        h = SHA256.new(data.encode())
        signature = pkcs1_15.new(key).sign(h)
        return data.encode() + b"signature:" + signature

    # We assume the config file is well formed
    # Read the port corresponding to its id from the configuration port
    def __read_conf(self):
        publish_port = None
        file = open('../conf/miner_discovery.json')
        data = json.load(file)
        for client in data['clients']:
            port = client['port']
            if client['id'] == self.identity:
                publish_port = port
                pub_key = RSA.import_key(client['pub_key'])
                break
        if publish_port is None:
            raise Exception("No publish port for miner with id: " + str(self.identity))
        return publish_port, pub_key

class Transaction:
    def __init__(self, content, pub_key):
        self.content = content
        self.pub_key = pub_key.exportKey('PEM').decode()

    def get_json(self):
        data = {}
        data['data'] = self.content
        data['pub_key'] = self.pub_key
        return json.dumps(data, sort_keys=True)



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
