from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, ZmqEndpointType
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import json
import array
import logging
from constants import DELIVERY_DELAY, TRANSACTION_TAG, COMMIT_TAG, MALICIOUS_PROPOSAL_AGREEMENT_TAG, PROPOSAL_TAG, \
    REINFORCEMENT_TAG, PROPOSAL_COMMIT_TAG


class Broadcast:
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
            subscriber.subscribe(PROPOSAL_TAG.encode())
            subscriber.subscribe(COMMIT_TAG.encode())
            subscriber.subscribe(REINFORCEMENT_TAG.encode())
            subscriber.subscribe(TRANSACTION_TAG.encode())
            subscriber.subscribe(MALICIOUS_PROPOSAL_AGREEMENT_TAG.encode())
            subscriber.subscribe(PROPOSAL_COMMIT_TAG.encode())

    def broadcast(self, data, tag):
        logging.info("SNT %s", tag)
        signed_data = self.sign(data)
        self.publisher.publish(signed_data, tag.encode())

    def sign(self, data):
        filename = "../keys/miners/miner" + str(self.miner.id) + ".key"
        key = RSA.importKey(open(filename).read())
        h = SHA256.new(data.encode())
        signature = pkcs1_15.new(key).sign(h)
        message = {}
        message['content'] = data
        message['signature'] = list(signature)  # integer array
        return json.dumps(message).encode()


class BroadcastSubscriber(ZmqSubConnection):

    def __init__(self, factory, subscribe_endpoint, miner):
        ZmqSubConnection.__init__(self, factory, subscribe_endpoint)
        self.miner = miner

    def parse_message(self, message):
        content = json.loads(message.decode())['content']
        signature = array.array('B', json.loads(message.decode())['signature']).tostring()
        return content, signature

    def verify_signature(self, message, signature, tag):
        if tag == PROPOSAL_TAG.encode():
            key = RSA.import_key(json.loads(json.loads(message)['data'])['pub_key'])
        else:
            key = RSA.import_key(json.loads(message)['pub_key'])
        h = SHA256.new(message.encode())
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            print("The signature is not valid.")
            return False

    def gotMessage(self, message, tag):
        data, signature = self.parse_message(message)
        if self.verify_signature(data, signature, tag):
            if tag.decode() == PROPOSAL_TAG and DELIVERY_DELAY > 0:
                from twisted.internet import reactor
                reactor.callLater(DELIVERY_DELAY, self.miner.new_message, data, signature, tag.decode())
            else:
                self.miner.new_message(data, signature, tag.decode())

