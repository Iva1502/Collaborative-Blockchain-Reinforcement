from twisted.internet import reactor
import json
from blockchain import Blockchain
from reinforcement_pom import ReinforcementPOM
from hash import Hash
from states import Mining, MaliciousMining, MaliciousPureBlockchain, PureBlockchain
from broadcast import Broadcast
from Crypto.PublicKey import RSA
import logging
import datetime as dt
from constants import REINFORCEMENT_TAG, PROPOSAL_TAG, MALICIOUS_PROPOSAL_AGREEMENT_TAG, COMMIT_TAG, TRANSACTION_TAG, \
    PROPOSAL_COMMIT_TAG, REINFORCEMENT_INF_TAG, SWITCH_TH


class Stop:
    def __init__(self):
        self.stop = False

    def set_stop(self):
        self.stop = True


class Miner:
    def __init__(self, _id, faulty):
        self.id = _id
        self.__read_conf(self)
        self.blockchain = Blockchain(self.genesis_time, self.pure, self.depth_cancel_block != -1)
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
        self.already_found = 0
        self.start = True
        self.res_loggerM = self.setup_logger('results_loggerM'+str(self.id), 'results_logfileM'+str(self.id)+'.log')
        self.res_loggerH = self.setup_logger('results_loggerH' + str(self.id), 'results_logfileH' + str(self.id) + '.log')
        self.counter = 0
        self.t = dt.datetime.now()
        #self.mal_block = None

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
        mal = (self.malicious and (self.depth_cancel_block != -1)) or \
              (self.malicious and self.current_block[0] % 2 == 0 and self.pure and (self.depth_cancel_block == -1))
        #args: mal_flag, cancel_all=False, threshold_divisor=1:
        if self.start:
            self.start = False
            self.current_block = self.blockchain.get_last(mal, self.depth_cancel_block == -1, 5 if self.pure else 1)
        else:
            if (self.malicious or (self.blockchain.get_last(mal, self.depth_cancel_block == -1, 5 if self.pure else 1)[1].weight - self.current_block[1].weight > SWITCH_TH)):
                self.current_block = self.blockchain.get_last(mal, self.depth_cancel_block == -1,
                                                              5 if self.pure else 1)

        logging.info("start mining - depth %s", self.current_block[0])
        logging.info("start mining - hash %s", self.current_block[1].hash())
        print("start mining - depth ", self.current_block[0])
        print("start mining - hash ", self.current_block[1].hash())

        # if the honest guys start mining on top of a malicious block in any of the models the malicious succeeded
        #if depth_cancel_block is -1, it means it's the cancel all blocks version
        if self.depth_cancel_block != -1 and not self.malicious and self.current_block[1].malicious:
            logging.info("END: MALICIOUS WIN")
            print("END: MALICIOUS WIN")
            print('\a')
        if self.depth_cancel_block == -1 and not self.pure and not self.malicious and self.current_block[1].malicious:
            logging.info("WIN: MALICIOUS WIN on block %d", self.current_block[0])
        self.stop_mining = Stop()
        #if self.mal_block is None:
        reactor.callInThread(self.hash.mine, self.current_block[1], self.stop_mining)
        delta = dt.datetime.now() - self.t
        if delta.seconds >= 60:
            logging.info("Hashing frequency: %s", self.counter)
            self.counter = 0
            self.t = dt.datetime.now()

        #else:
         #   reactor.callInThread(self.hash.mine, self.mal_block, self.stop_mining)


    def start_new_mal_mining(self, c_block):
        logging.info("start mal HIDEN mining on top of - hash %s", c_block.hash())
        print("start mal HIDEN mining on top of - hash ", c_block.hash())
        #if depth_cancel_block is -1, it means it's the cancel all blocks strategy
        self.stop_mining = Stop()
        #if self.mal_block is None:
        reactor.callInThread(self.hash.mine, c_block, self.stop_mining)

    def new_hash_found(self, val, nonce):
        self.state.hash_value_process(val, nonce)
        #val is the hash that is found

    def new_message(self, data, signature, tag):
        if tag == PROPOSAL_TAG:
            logging.info("RCV proposal")
            self.state.proposal_process(data)
        elif tag == REINFORCEMENT_TAG:
            logging.info("RCV reinforcement")
            self.state.reinforcement_process(data, signature)
        elif tag == REINFORCEMENT_INF_TAG:
            logging.info("RCV reinforcement info")
            self.state.reinforcement_info_process(data, signature)
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

    def setup_logger(self, name, log_file, level=logging.INFO):
        """Function setup as many loggers as you want"""

        formatter = logging.Formatter('%(asctime)s %(message)s')
        formatter.datefmt = '%s'
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)

        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.addHandler(handler)

        return logger
