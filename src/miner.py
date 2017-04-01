from twisted.internet import reactor
import json
from blockchain import Blockchain
from hash import Hash
from states import Mining
from broadcast import Broadcast
from Crypto.PublicKey import RSA


class Stop:
    def __init__(self):
        self.stop = False

    def set_stop(self):
        self.stop = True


class Miner:
    def __init__(self, _id):
        self.id = _id
        self.blockchain = Blockchain()
        self.current_block = None
        self.hash = Hash(self)
        self.state = Mining(self)
        self.stop_mining = None
        self.nonce_list = []
        self.transaction_list = []
        self.__read_conf(self)
        self.broadcast = Broadcast(self)

    def __read_conf(self, _miner):
        subscribe_ports = []
        _miner.publish_port = None
        file = open('../conf/miner_discovery.json')
        data = json.load(file)
        # read the ports of the miners
        for miner in data['miners']:
            port = miner["port"]
            if miner['id'] == _miner.id:
                _miner.publish_port = port
                _miner.public_key = RSA.import_key(miner['pub_key'].encode())
            else:
                subscribe_ports.append(port)
        if _miner.publish_port is None:
            raise Exception("No publish port for miner with id: " + str(_miner.id))
        # read the ports of the clients
        for client in data['clients']:
            port = client['port']
            subscribe_ports.append(port)
        _miner.subscribe_ports = subscribe_ports

    def stop(self):
        if self.stop_mining is not None:
            self.stop_mining.set_stop()

    def run(self):
        print("Miner was run")
        self.start_new_mining()

    def start_new_mining(self):
        self.current_block = self.blockchain.get_last()
        self.stop_mining = Stop()
        reactor.callInThread(self.hash.mine, self.current_block[1], self.stop_mining)

    def new_hash_found(self, val, nonce):
        self.state.hash_value_process(val, nonce)

    def new_message(self, value, type):
        if type == "proposal":
            self.state.proposal_process(value)
        elif type == "commit":
            self.state.commit_process(value)
        elif type == "reinforcement":
            self.state.reinforcement_process(value)
        elif type == "transaction":
            self.state.transaction_process(value)