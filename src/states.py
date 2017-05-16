import json
from blockchain import CommitBlock, ProposeBlock
from twisted.internet import reactor
from constants import COMMIT_TH, REINF_TH, SWITCH_TH, REINF_TIMEOUT, COMMIT_TIMEOUT, COMMIT_TAG, PROPOSAL_TAG, \
    MALICIOUS_PROPOSAL_AGREEMENT_TAG, REINFORCEMENT_TAG
from hash import compute_hash, check_hash
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from time import time
import logging


class State:
    def __init__(self, miner):
        self.miner = miner

    def hash_value_process(self, value, nonce):
        pass

    def message_process(self, type, value):
        pass

    def proposal_process(self, value):
        pass

    def reinforcement_process(self, value, sign):
        pass

    def commit_process(self, value):
        pass

    def proposal_commit_process(self, value):
        pass

    def transaction_process(self, value):
        self.miner.transaction_list.append(value)

    def malicious_proposal_agreement_process(self, value):
        pass

    def found_pom(self, faulty_reinforcements):
        print('\a')
        print(len(faulty_reinforcements))
        for reinforcement in faulty_reinforcements:
            print(reinforcement)


class PureBlockchain(State):
    #Change weights
    def __init__(self, miner):
        super(PureBlockchain, self).__init__(miner)
        self.miner.transaction_list = []
        #print("MINING")

    def restart(self):
        self.miner.stop_mining.set_stop()
        self.miner.transaction_list = []
        self.miner.start_new_mining()

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce):
            if int(value, 16) < COMMIT_TH:
                print("Hash found")
                self.miner.stop_mining.set_stop()
                p_block = ProposeBlock(nonce, self.miner.public_key.exportKey('PEM').decode(),
                                       list(self.miner.transaction_list))
                c_block = CommitBlock()
                message = {}
                message['previous'] = {}
                message['propose_data'] = p_block.get_json()
                message['commit_data'] = c_block.get_json()
                message['previous']['hash'] = self.miner.current_block[1].hash()
                message['previous']['depth'] = self.miner.current_block[0]
                self.miner.blockchain.add_propose_block(p_block, self.miner.current_block[0],
                                                        self.miner.current_block[1].hash())
                self.miner.blockchain.add_commit_block(c_block, self.miner.current_block[0]+1,
                                                       p_block.hash(), p_block.pub_key)
                self.miner.current_block = (self.miner.current_block[0]+2, c_block)
                #CHANGE TAG
                self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_TAG)
                self.restart()
                print("Switch to another mining")

    def block_process(self, value):
        message_content = json.loads(value)
        p_block = ProposeBlock()
        p_block.from_json(message_content['propose_data'])
        self.miner.blockchain.add_propose_block(p_block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        c_block = CommitBlock()
        c_block.from_json(message_content['commit_data'])
        self.miner.blockchain.add_commit_block(c_block, message_content['previous']['depth']+1,
                                                p_block.hash(), p_block.pub_key)
        #Do we need it?
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.restart()
            return
        if c_block.weight - self.miner.current_block[1].weight >= SWITCH_TH:
            self.restart()


class MaliciousPureBlockchain(State):
    #Change weights
    def __init__(self, miner):
        super(MaliciousPureBlockchain, self).__init__(miner)
        self.miner.transaction_list = []
        self.i_should_propose = False
        self.timestamp = None
        self.block_appeared = False
        self.nonce = None
        #print("MINING")

    def restart(self):
        self.miner.stop_mining.set_stop()
        self.miner.transaction_list = []
        self.miner.start_new_mining()

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def malicious_proposal_agreement_process(self, value):
        message_content = json.loads(value)
        if self.timestamp is None or message_content['timestamp'] < self.timestamp:
            self.timestamp = message_content['timestamp']
            self.i_should_propose = False

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce) and self.miner.current_block[0] >= self.miner.depth_cancel_block - 1:
            if int(value, 16) < COMMIT_TH and self.timestamp is None:
                if not self.block_appeared:
                    ts = time()
                    my_prop = {
                        'timestamp': ts
                    }
                    self.timestamp = ts
                    self.nonce = nonce
                    self.miner.broadcast.broadcast(json.dumps(my_prop), MALICIOUS_PROPOSAL_AGREEMENT_TAG)
                    self.i_should_propose = True
                else:
                    print("Hash found")
                    self.miner.stop_mining.set_stop()
                    p_block = ProposeBlock(nonce, self.miner.public_key.exportKey('PEM').decode(),
                                           list(self.miner.transaction_list))
                    c_block = CommitBlock()
                    p_block.malicious = True
                    c_block.malicious = True
                    message = {}
                    message['previous'] = {}
                    message['propose_data'] = p_block.get_json()
                    message['commit_data'] = c_block.get_json()
                    message['previous']['hash'] = self.miner.current_block[1].hash()
                    message['previous']['depth'] = self.miner.current_block[0]
                    self.miner.blockchain.add_propose_block(p_block, self.miner.current_block[0],
                                                            self.miner.current_block[1].hash())
                    self.miner.blockchain.add_commit_block(c_block, self.miner.current_block[0]+1,
                                                           p_block.hash(), p_block.pub_key)
                    self.miner.current_block = (self.miner.current_block[0]+2, c_block)
                    #CHANGE TAG
                    self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_TAG)
                    self.restart()
                    print("Switch to another mining")

    def block_process(self, value):
        message_content = json.loads(value)
        p_block = ProposeBlock()
        p_block.from_json(message_content['propose_data'])
        self.miner.blockchain.add_propose_block(p_block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        c_block = CommitBlock()
        c_block.from_json(message_content['commit_data'])
        self.miner.blockchain.add_commit_block(c_block, message_content['previous']['depth']+1,
                                                p_block.hash(), p_block.pub_key)
        if message_content['previous']['depth']+1 == self.miner.depth_cancel_block and not c_block.malicious:
            self.block_appeared = True
            if self.i_should_propose:
                p_block = ProposeBlock(self.nonce, self.miner.public_key.exportKey('PEM').decode(),
                                       list(self.miner.transaction_list))
                c_block = CommitBlock()
                p_block.malicious = True
                c_block.malicious = True
                message = {}
                message['previous'] = {}
                message['propose_data'] = p_block.get_json()
                message['commit_data'] = c_block.get_json()
                message['previous']['hash'] = self.miner.current_block[1].hash()
                message['previous']['depth'] = self.miner.current_block[0]
                self.miner.blockchain.add_propose_block(p_block, self.miner.current_block[0],
                                                        self.miner.current_block[1].hash())
                self.miner.blockchain.add_commit_block(c_block, self.miner.current_block[0] + 1,
                                                       p_block.hash(), p_block.pub_key)
                self.miner.current_block = (self.miner.current_block[0] + 2, c_block)
                # CHANGE TAG
                self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_TAG)
                self.restart()

        if message_content['previous']['depth'] < self.miner.depth_cancel_block:
            self.restart()
            return
        if message_content['previous']['hash'] == self.miner.current_block[1].hash() and c_block.malicious:
            self.restart()
            return
        if c_block.weight - self.miner.current_block[1].weight >= SWITCH_TH and c_block.malicious:
            self.restart()


class Mining(State):
    def __init__(self, miner):
        logging.info("MINING state")
        super(Mining, self).__init__(miner)
        self.miner.transaction_list = []
        self.miner.nonce_list = []

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce):
            if int(value, 16) < COMMIT_TH:
                logging.info("hash found")
                print("Hash found")
                self.miner.stop_mining.set_stop()
                block = ProposeBlock(nonce, self.miner.public_key.exportKey('PEM').decode(),
                                     list(self.miner.transaction_list))
                message = {}
                message['previous'] = {}
                message['data'] = block.get_json()
                message['previous']['hash'] = self.miner.current_block[1].hash()
                message['previous']['depth'] = self.miner.current_block[0]
                self.miner.blockchain.add_propose_block(block, self.miner.current_block[0],
                                                        self.miner.current_block[1].hash())
                self.miner.current_block = (self.miner.current_block[0] + 1, block)
                self.miner.state = ReinforcementCollecting(self.miner)
                self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_TAG)
                print("Switch to reinforcement collection")
            else:
                self.miner.nonce_list.append(nonce)

    def proposal_process(self, value):
        print("Proposal was received")
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.miner.current_block = (message_content['previous']['depth']+1, block)
            self.miner.stop_mining.set_stop()
            self.miner.state = ReinforcementSent(self.miner)
            if len(self.miner.nonce_list) > 0:
                message = {}
                message['nonce_list'] = list(self.miner.nonce_list)
                message['hash'] = self.miner.current_block[1].hash()
                message['hash_commit'] = message_content['previous']['hash']
                message['depth'] = self.miner.current_block[0]
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)

            print("Switch to reinforcement sent")

    def commit_process(self, value):
        print("Commit was received")
        self.miner.reinforcement_pom.check_reinforcements_commit(value)
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'], message_content['pub_key'])
        if block.weight - self.miner.current_block[1].weight >= SWITCH_TH:
            logging.info("Switching branch")
            self.miner.stop_mining.set_stop()
            self.miner.transaction_list = []
            self.miner.nonce_list = []
            self.miner.start_new_mining()

    def reinforcement_process(self, value, sign):
        print("Reinforcement was received")
        # FIXME I have to add this to all states, right?
        self.miner.reinforcement_pom.new_reinforcement(value, sign)


class MaliciousMining(State):
    def __init__(self, miner):
        logging.info("MALICIOUS MINING state")
        super(MaliciousMining, self).__init__(miner)
        self.miner.transaction_list = []
        self.miner.nonce_list = []
        self.i_should_propose = False
        self.timestamp = None
        self.nonce = None   # the nonce the miner will use when proposing the malicious block
        self.block_appeared = False
        print("MINING MALICIOUS")

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def malicious_proposal_agreement_process(self, value):
        message_content = json.loads(value)
        if self.timestamp is None or message_content['timestamp'] < self.timestamp:
            self.timestamp = message_content['timestamp']
            self.i_should_propose = False
            if self.nonce is not None:
                self.miner.nonce_list.append(self.nonce)

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce) and self.miner.current_block[0] >= self.miner.depth_cancel_block - 1:
            if int(value, 16) < COMMIT_TH and self.timestamp is None:
                logging.info("hash found")
                print("hash found")
                if not self.block_appeared:
                    ts = time()
                    my_prop = {
                        'timestamp': ts,
                        'pub_key': self.miner.public_key.exportKey('PEM').decode()
                    }
                    self.timestamp = ts
                    self.nonce = nonce
                    self.i_should_propose = True
                    self.miner.broadcast.broadcast(json.dumps(my_prop), MALICIOUS_PROPOSAL_AGREEMENT_TAG)
                else:
                    self.miner.stop_mining.set_stop()
                    block = ProposeBlock(nonce, self.miner.public_key.exportKey('PEM').decode(),
                                         list(self.miner.transaction_list))
                    block.malicious = True
                    message = {}
                    message['previous'] = {}
                    message['data'] = block.get_json()
                    message['previous']['hash'] = self.miner.current_block[1].hash()
                    message['previous']['depth'] = self.miner.current_block[0]
                    self.miner.blockchain.add_propose_block(block, self.miner.current_block[0],
                                                            self.miner.current_block[1].hash())
                    self.miner.current_block = (self.miner.current_block[0] + 1, block)
                    self.miner.state = ReinforcementCollecting(self.miner)
                    self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_TAG)
                    print("Proposed")
                    print("Switch to reinforcement collection")
            # if other malicious miner already proposed or the hash isn't lower than the COMMIT_TH the nonce is saved
            else:
                self.miner.nonce_list.append(nonce)

    def proposal_process(self, value):
        print("Proposal was received")
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            if block.malicious:
                self.miner.stop_mining.set_stop()
                if len(self.miner.nonce_list) > 0:
                    message = {}
                    message['nonce_list'] = list(self.miner.nonce_list)
                    message['hash'] = self.miner.current_block[1].hash()
                    message['hash_commit'] = message_content['previous']['hash']
                    message['depth'] = self.miner.current_block[0]
                    message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                    self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)
                self.miner.state = ReinforcementSent(self.miner)
                self.miner.current_block = (message_content['previous']['depth'] + 1, block)
                print("Switch to reinforcement sent")

    def commit_process(self, value):
        print("Commit was received")
        self.miner.reinforcement_pom.check_reinforcements_commit(value)
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'], message_content['pub_key'])

        if (block.malicious and block.weight - self.miner.current_block[1].weight >= SWITCH_TH) or \
                        message_content['previous']['depth'] < self.miner.depth_cancel_block:
            self.miner.stop_mining.set_stop()
            self.miner.transaction_list = []
            self.miner.nonce_list = []
            self.miner.start_new_mining()

        elif message_content['previous']['depth'] == self.miner.depth_cancel_block and not block.malicious:
            self.block_appeared = True
            if self.i_should_propose:
                self.miner.stop_mining.set_stop()
                block = ProposeBlock(self.nonce, self.miner.public_key.exportKey('PEM').decode(),
                                     list(self.miner.transaction_list))
                block.malicious = True
                message = {}
                message['previous'] = {}
                message['data'] = block.get_json()
                message['previous']['hash'] = self.miner.current_block[1].hash()
                message['previous']['depth'] = self.miner.current_block[0]
                self.miner.blockchain.add_propose_block(block, self.miner.current_block[0],
                                                        self.miner.current_block[1].hash())
                self.miner.current_block = (self.miner.current_block[0] + 1, block)
                self.miner.state = ReinforcementCollecting(self.miner)
                self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_TAG)

    def reinforcement_process(self, value, sign):
        print("Reinforcement was received")
        self.miner.reinforcement_pom.new_reinforcement(value, sign)


class ReinforcementSent(State):
    def __init__(self, miner):
        logging.info("REINFORCEMENT SENT state")
        super(ReinforcementSent, self).__init__(miner)
        self.timeout = reactor.callLater(COMMIT_TIMEOUT, self.mining_switch)
        #print("REINF_SENT")

    def mining_switch(self):
        if self.miner.malicious:
            self.miner.state = MaliciousMining(self.miner)
            self.miner.state.block_appeared = True
        else:
            self.miner.state = Mining(self.miner)
        self.miner.start_new_mining()
        print("Switch to mining")

    def proposal_process(self, value):
        print("Proposal was received")
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        if self.miner.faulty:
            if message_content['previous']['hash'] == self.miner.current_block[1].prev_link.hash():
                if len(self.miner.nonce_list) > 0:
                    print("reinforcing again")
                    message = {}
                    message['nonce_list'] = list(self.miner.nonce_list)
                    message['hash'] = block.hash()
                    message['hash_commit'] = message_content['previous']['hash']
                    message['depth'] = message_content['previous']['depth'] + 1
                    message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                    self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)

    def commit_process(self, value):
        print("Commit was received")
        self.miner.reinforcement_pom.check_reinforcements_commit(value)
        if self.timeout.active():
            self.timeout.cancel()
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'], message_content['pub_key'])
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.mining_switch()

    def reinforcement_process(self, value, sign):
        print("Reinforcement was received")
        # FIXME I have to add this to all states, right?
        self.miner.reinforcement_pom.new_reinforcement(value, sign)


class ReinforcementCollecting(State):
    def __init__(self, miner):
        logging.info("REINFORCEMENT COLLECTING state")
        super(ReinforcementCollecting, self).__init__(miner)
        self.received_reinforcements = {}
        if len(self.miner.nonce_list) > 0:
            message = {}
            message['nonce_list'] = list(self.miner.nonce_list)
            message['hash'] = self.miner.current_block[1].hash()
            message['depth'] = self.miner.current_block[0]
            message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
            filename = "../keys/miners/miner" + str(self.miner.id) + ".key"
            key = RSA.importKey(open(filename).read())
            json_message = json.dumps(message)
            h = SHA256.new(json_message.encode())
            signature = pkcs1_15.new(key).sign(h)
            dict_to_add = {}
            dict_to_add['nonces'] = list(self.miner.nonce_list)
            dict_to_add['signature'] = list(signature)
            self.received_reinforcements[self.miner.public_key.exportKey('PEM').decode()] = dict_to_add
        print("My reinforcement", len(self.miner.nonce_list))
        reactor.callLater(REINF_TIMEOUT, self.committing)

    def committing(self):
        if len(self.received_reinforcements):
            print("Reinforcement was received from ", len(self.received_reinforcements))
        else:
            print("Reinforcement was not received")
        block = CommitBlock(self.received_reinforcements, self.miner.reinforcement_pom.get_poms())
        if self.miner.malicious:
            block.malicious = True
        message = {}
        message['previous'] = {}
        message['data'] = block.get_json()
        # print(message['data'])
        message['previous']['hash'] = self.miner.current_block[1].hash()
        message['previous']['depth'] = self.miner.current_block[0]
        message['hash_last_commit'] = self.miner.current_block[1].prev_link.hash()
        message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
        self.miner.blockchain.add_commit_block(block, self.miner.current_block[0], self.miner.current_block[1].hash(),
                                               self.miner.public_key.exportKey('PEM').decode())
        if self.miner.malicious:
            self.miner.state = MaliciousMining(self.miner)
            self.miner.state.block_appeared = True
        else:
            self.miner.state = Mining(self.miner)
        self.miner.start_new_mining()
        self.miner.broadcast.broadcast(json.dumps(message), COMMIT_TAG)
        print("Switch to mining")

    def proposal_process(self, value):
        print("Proposal was received")
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        if self.miner.faulty:
            if message_content['previous']['hash'] == self.miner.current_block[1].prev_link.hash():
                if len(self.miner.nonce_list) > 0:
                    print("reinforcing again")
                    message = {}
                    message['nonce_list'] = list(self.miner.nonce_list)
                    message['hash'] = block.hash()
                    message['hash_commit'] = message_content['previous']['hash']
                    message['depth'] = message_content['previous']['depth'] + 1
                    message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                    self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)

    def reinforcement_process(self, value, sign):
        print("Reinforcement was received")
        self.miner.reinforcement_pom.new_reinforcement(value, sign)
        message_content = json.loads(value)
        if message_content['hash'] == self.miner.current_block[1].hash():
            checked = []
            for nonce in message_content['nonce_list']:
                if check_hash(self.miner.current_block[1].prev_link, nonce,
                                   RSA.import_key(message_content['pub_key']), REINF_TH):
                    checked.append(nonce)
                else:
                    print('BAD HASH')
            if len(checked) > 0:
                if message_content['pub_key'] in self.received_reinforcements.keys():
                    self.received_reinforcements[message_content['pub_key']]['nonces'].extend(checked)
                else:
                    dict_to_add = {}
                    dict_to_add['nonces'] = checked
                    dict_to_add['signature'] = list(sign)
                    self.received_reinforcements[message_content['pub_key']] = dict_to_add

    def commit_process(self, value):
        print("Commit was received")
        self.miner.reinforcement_pom.check_reinforcements_commit(value)
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'], message_content['pub_key'])
