import json
from blockchain import CommitBlock, ProposeBlock
from twisted.internet import reactor
from constants import COMMIT_TH, REINF_TH, SWITCH_TH, REINF_TIMEOUT, COMMIT_TIMEOUT
from hash import compute_hash
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

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

    def transaction_process(self, value):
        self.miner.transaction_list.append(value)

    def check_hash(self, block, nonce, pub_key, th):
        return int(compute_hash(block.hash(hex=False), nonce, pub_key.exportKey('DER')), 16) < th


class Mining(State):
    def __init__(self, miner):
        super(Mining, self).__init__(miner)
        self.miner.transaction_list = []
        self.miner.nonce_list = []
        #print("MINING")

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce):
            if int(value, 16) < COMMIT_TH:
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
                self.miner.broadcast.broadcast(json.dumps(message), "proposal")
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
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                self.miner.broadcast.broadcast(json.dumps(message), "reinforcement")
            print("Switch to reinforcement sent")

    def commit_process(self, value):
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'])
        if block.weight - self.miner.current_block[1].weight >= SWITCH_TH:
            print("Reset mining")
            self.miner.stop_mining.set_stop()
            self.miner.transaction_list = []
            self.miner.nonce_list = []
            self.miner.start_new_mining()


class ReinforcementSent(State):
    def __init__(self, miner):
        super(ReinforcementSent, self).__init__(miner)
        self.timeout = reactor.callLater(COMMIT_TIMEOUT, self.mining_switch)
        #print("REINF_SENT")

    def mining_switch(self):
        self.miner.state = Mining(self.miner)
        self.miner.start_new_mining()
        print("Switch to mining")

    def proposal_process(self, value):
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])

    def commit_process(self, value):
        print("Commit was received")
        if self.timeout.active():
            self.timeout.cancel()
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'])
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.mining_switch()


class ReinforcementCollecting(State):
    def __init__(self, miner):
        super(ReinforcementCollecting, self).__init__(miner)
        self.received_reinforcements = {}
        if len(self.miner.nonce_list) > 0:
            message = {}
            message['nonce_list'] = list(self.miner.nonce_list)
            message['hash'] = self.miner.current_block[1].hash()
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
        reactor.callLater(REINF_TIMEOUT, self.commiting)

    def commiting(self):
        if len(self.received_reinforcements):
            print("Reinforcement was received from ", len(self.received_reinforcements))
        else:
            print("Reinforcement was not received")
        block = CommitBlock(self.received_reinforcements)
        message = {}
        message['previous'] = {}
        message['data'] = block.get_json()
        print(message['data'])
        message['previous']['hash'] = self.miner.current_block[1].hash()
        message['previous']['depth'] = self.miner.current_block[0]
        message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
        self.miner.blockchain.add_commit_block(block, self.miner.current_block[0], self.miner.current_block[1].hash())
        self.miner.state = Mining(self.miner)
        self.miner.start_new_mining()
        self.miner.broadcast.broadcast(json.dumps(message), "commit")
        print("Switch to mining")

    def proposal_process(self, value):
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])

    def reinforcement_process(self, value, sign):
        message_content = json.loads(value)
        if message_content['hash'] == self.miner.current_block[1].hash():
            checked = []
            for nonce in message_content['nonce_list']:
                if self.check_hash(self.miner.current_block[1].prev_link, nonce,
                                   RSA.import_key(message_content['pub_key']), REINF_TH):
                    checked.append(nonce)
                else:
                    print('BAD HASH')
            if len(checked) > 0:
                dict_to_add = {}
                dict_to_add['nonces'] = checked
                dict_to_add['signature'] = list(sign)
                self.received_reinforcements[message_content['pub_key']] = dict_to_add

    def commit_process(self, value):
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'])
