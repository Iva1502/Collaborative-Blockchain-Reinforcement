from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, ZmqEndpointType
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import json

class Broadcast():

    def __init__(self, miner):
        # create a factory
        self.miner = miner
        self.factory = ZmqFactory()
        # create a connection to publish
        publish_endpoint = ZmqEndpoint(ZmqEndpointType.bind, "tcp://127.0.0.1:" + miner.publish_port)
        self.publisher = ZmqPubConnection(self.factory, publish_endpoint)
        # create connections to subscribe
        self.subscribers = []
        print("the ports subscribed are:")
        print(miner.subscribe_ports)
        for subscribe_port in miner.subscribe_ports:
            subscribe_endpoint = ZmqEndpoint(ZmqEndpointType.connect, "tcp://127.0.0.1:" + subscribe_port)
            subscriber = BroadcastSubscriber(self.factory, subscribe_endpoint, miner)
            self.subscribers.append(subscriber)
            # subcribe to the types of events
            subscriber.subscribe(b"proposal")
            subscriber.subscribe(b"commit")
            subscriber.subscribe(b"reinforcement")
            subscriber.subscribe(b"transaction")

    def broadcast(self, data, tag):
        if tag == "proposal":
            signed_data = self.sign(data)
            #TODO verify transaction and implemented integrity on the transactions
            self.publisher.publish(signed_data, tag.encode())
        else:
            self.publisher.publish(data.encode(), tag.encode())

    def sign(self, data):
        filename = "../keys/miner"+str(self.miner.id)+".key"
        key = RSA.importKey(open(filename).read())
        h = SHA256.new(data.encode())
        signature = pkcs1_15.new(key).sign(h)
        return data.encode() + b"signature:" + signature


class BroadcastSubscriber(ZmqSubConnection):

    def __init__(self, factory, subscribe_endpoint, miner):
        ZmqSubConnection.__init__(self, factory, subscribe_endpoint)
        self.miner = miner

    def parse_message(self, message):
        message_final_index = message.rfind(b"signature:")
        signature_initial_index = message_final_index + len("signature:")
        return message[:message_final_index], message[signature_initial_index:]

    def verify_signature(self, message, signature):
        key = RSA.import_key(json.loads(json.loads(message.decode())['data'])['pub_key'])
        h = SHA256.new(message)
        try:
            pkcs1_15.new(key).verify(h, signature)
            print("The signature is valid.")
            return True
        except (ValueError, TypeError):
            print("The signature is not valid.")
            return False

    def gotMessage(self, message, tag):
        if tag == b"proposal":
            data, signature = self.parse_message(message)
            if self.verify_signature(data, signature):
                self.miner.new_message(data.decode(), tag.decode())
        else:
            self.miner.new_message(message.decode(), tag.decode())
