from twisted.internet import reactor
import json
from blockchain import Blockchain
from reinforcement_pom import ReinforcementPOM
from hash import Hash
from states import Mining, MaliciousMining, MaliciousPureBlockchain, PureBlockchain
from broadcast import Broadcast
from Crypto.PublicKey import RSA
import logging
from constants import REINFORCEMENT_TAG, PROPOSAL_TAG, MALICIOUS_PROPOSAL_AGREEMENT_TAG, COMMIT_TAG, TRANSACTION_TAG, \
    PROPOSAL_COMMIT_TAG


class Stop:
    def __init__(self):
        self.stop = False

    def set_stop(self):
        self.stop = True


class Miner:
    def __init__(self, _id, faulty):
        self.id = _id
        self.__read_conf(self)
        self.blockchain = Blockchain(self.genesis_time, self.pure)
        self.current_block = self.blockchain.get_last()
        self.hash = Hash(self)

        self.stop_mining = None
        self.nonce_list = []
        self.transaction_list = []
        if self.pure:
            if self.malicious:
                self.state = MaliciousPureBlockchain(self)
            else:
                self.state = PureBlockchain(self)
        else:
            if self.malicious:
                self.state = MaliciousMining(self)
            else:
                self.state = Mining(self)
        self.broadcast = Broadcast(self)
        self.reinforcement_pom = ReinforcementPOM(self)
        self.faulty = faulty

    def __read_conf(self, _miner):
        subscribe_ports = []
        _miner.publish_port = None
        with open('../conf/miner_discovery.json') as file:
            data = json.load(file)
        _miner.depth_cancel_block = data['cancel_block']
        _miner.genesis_time = data['genesis_time']
        _miner.pure = data['pure_version']
        # read the ports of the miners
        for miner in data['miners']:
            port = miner["port"]
            if miner['id'] == _miner.id:
                _miner.publish_port = port
                _miner.public_key = RSA.import_key(miner['pub_key'])
                _miner.malicious = miner['malicious']
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
        self.current_block = self.blockchain.get_last(self.malicious)
        logging.info("start mining - depth %s", self.current_block[0])
        logging.info("start mining - hash %s", self.current_block[1].hash())
        self.stop_mining = Stop()
        reactor.callInThread(self.hash.mine, self.current_block[1], self.stop_mining)

    def new_hash_found(self, val, nonce):
        self.state.hash_value_process(val, nonce)

    def new_message(self, data, signature, tag):
        if tag == PROPOSAL_TAG:
            logging.info("RCV proposal")
            self.state.proposal_process(data)
        elif tag == REINFORCEMENT_TAG:
            logging.info("RCV reinforcement")
            self.state.reinforcement_process(data, signature)
        elif tag == COMMIT_TAG:
            logging.info("RCV commit")
            self.state.commit_process(data)
        elif tag == PROPOSAL_COMMIT_TAG:
            logging.info("RCV proposal_commit")
            self.state.proposal_commit_process(data)
        elif tag == TRANSACTION_TAG:
            self.state.transaction_process(data)
        elif tag == MALICIOUS_PROPOSAL_AGREEMENT_TAG and self.malicious:
            logging.info("RCV malicious_prop_agreement")
            self.state.malicious_proposal_agreement_process(data)
