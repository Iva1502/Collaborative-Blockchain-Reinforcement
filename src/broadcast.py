from txzmq import ZmqEndpoint, ZmqFactory, ZmqPubConnection, ZmqSubConnection, ZmqEndpointType


class Broadcast():

    def __init__(self, miner):
        # create a factory
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
        print("broadcasting: ")
        self.publisher.publish(data.encode(), tag.encode())


class BroadcastSubscriber(ZmqSubConnection):

    def __init__(self, factory, subscribe_endpoint, miner):
        ZmqSubConnection.__init__(self, factory, subscribe_endpoint)
        self.miner = miner

    def gotMessage(self, message, tag):
        self.miner.new_message(message.decode(), tag.decode())
