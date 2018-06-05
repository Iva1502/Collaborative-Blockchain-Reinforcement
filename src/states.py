import json
from blockchain import CommitBlock, ProposeBlock
from twisted.internet import reactor
from constants import COMMIT_TH, REINF_TH, SWITCH_TH, REINF_TIMEOUT, COMMIT_TIMEOUT, COMMIT_TAG, PROPOSAL_TAG, \
    MALICIOUS_PROPOSAL_AGREEMENT_TAG, REINFORCEMENT_TAG, PROPOSAL_COMMIT_TAG, REINFORCEMENT_INF_TAG
from hash import compute_hash, check_hash
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from time import time
import logging
#import main



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

    def reinforcement_info_process(self, value, sign):
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
        logging.info("PURE BLOCKCHAIN state")
        super(PureBlockchain, self).__init__(miner)
        self.miner.transaction_list = []

    def restart(self):
        self.miner.stop()
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
                logging.info("hash found")
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
                if c_block.malicious:
                    msg = ', ' + str(c_block.weight)
                    self.miner.res_loggerM.info(msg)
                else:
                    msg = ', ' + str(c_block.weight)
                    self.miner.res_loggerH.info(msg)
                self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_COMMIT_TAG)
                self.restart()

    def proposal_commit_process(self, value):
        message_content = json.loads(value)
        p_block = ProposeBlock()
        p_block.from_json(message_content['propose_data'])
        self.miner.blockchain.add_propose_block(p_block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        c_block = CommitBlock()
        c_block.from_json(message_content['commit_data'])
        self.miner.blockchain.add_commit_block(c_block, message_content['previous']['depth'] + 1,
                                                p_block.hash(), p_block.pub_key)
        if c_block.malicious:
            msg = ', ' + str(c_block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg =  ', ' + str(c_block.weight)
            self.miner.res_loggerH.info(msg)
        # We only need this condition if SWITCH_TH != 0
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.restart()
        elif c_block.weight - self.miner.current_block[1].weight > SWITCH_TH:
            self.restart()


class MaliciousPureBlockchain(State):
    #tic-tac. once in two rounds reset flag and get heaviest block among all
    #Change weights
    def __init__(self, miner):
        logging.info("MALICIOUS PURE BLOCKCHAIN state")
        super(MaliciousPureBlockchain, self).__init__(miner)
        self.miner.transaction_list = []
        self.i_should_propose = False
        self.timestamp = None
        self.block_appeared = False
        # if block_appeared set to true it means some honest miner found a block and the malicious one will try to cancel it
        self.nonce = None
        self.prop2_flag = False
        if self.miner.depth_cancel_block == -1:
            self.cancel_all = True
        else:
            self.cancel_all = False

    # in order to start new mining on top of the heaviest chain
    def restart(self):
        self.miner.stop()
        self.miner.transaction_list = []
        self.timestamp = None
        self.miner.start_new_mining()
        self.prop2_flag = False
        if not self.cancel_all:
            self.block_appeared = True

    def restart_block(self,block):
        self.miner.stop()
        self.miner.transaction_list = []
        self.prop2_flag= True
        self.timestamp = None
        self.miner.start_new_mal_mining(block)
        if not self.cancel_all:
            self.block_appeared = True

    # to check if the hash is valid
    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    # when the miner receives a message with tag == MALICIOUS_PROPOSAL_AGREEMENT_TAG
    def malicious_proposal_agreement_process(self, value):
        message_content = json.loads(value)
        if message_content['depth'] == self.miner.current_block[0]:
            if self.timestamp is None or message_content['timestamp'] < self.timestamp:
                self.timestamp = message_content['timestamp']
                self.i_should_propose = False
                c_block = CommitBlock()
                c_block.from_json(message_content['commit_data'])
                self.restart_block(c_block)

    # when the miner finds a new hash, this method is being called
    def hash_value_process(self, value, nonce):
        # value is the hash of the new block
        # block[0] is the depth block[1] is the block itself
        # if the hash is valid and the current depth is "greater than" the cancel_block value
        if self.is_hash_fresh(value, nonce) and self.miner.current_block[0] >= self.miner.depth_cancel_block - 1:
            if int(value, 16) < COMMIT_TH and (self.timestamp is None or self.prop2_flag):
                print("Hash found")
                logging.info("hash found")
                # if the honest didn't append a new block yet, send a mal prop
                p_block = ProposeBlock(nonce, self.miner.public_key.exportKey('PEM').decode(),
                                       list(self.miner.transaction_list))
                c_block = CommitBlock()
                p_block.malicious = True
                c_block.malicious = True
                self.miner.stop_mining.set_stop()
                if not self.block_appeared:
                    ts = int(time())
                    my_prop = {}
                    my_prop['timestamp'] = ts
                    my_prop['depth'] = self.miner.current_block[0]
                    my_prop['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                    my_prop['propose_data'] = p_block.get_json()
                    my_prop['commit_data'] = c_block.get_json()
                    self.timestamp = ts
                    self.nonce = nonce
                    self.miner.broadcast.broadcast(json.dumps(my_prop), MALICIOUS_PROPOSAL_AGREEMENT_TAG)
                    self.i_should_propose = True
                # the honest has broadcasted a new block so the malicious needs to do so too
                else:
                    self.miner.stop_mining.set_stop()
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
                    self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_COMMIT_TAG)
                    if c_block.malicious:
                        msg = ', ' + str(c_block.weight)
                        self.miner.res_loggerM.info(msg)
                    else:
                        msg = ', ' + str(c_block.weight)
                        self.miner.res_loggerH.info(msg)
                    if self.cancel_all and self.miner.current_block[0] % 2 == 1:
                        self.block_appeared = False
                        # this means that the malicious found the second block first
                        logging.info("WIN: MALICIOUS WIN")
                    self.restart()
                    print("Switch to another mining")


    def proposal_commit_process(self, value):
        print("PROP COMMIT received")
        message_content = json.loads(value)
        p_block = ProposeBlock()
        p_block.from_json(message_content['propose_data'])
        self.miner.blockchain.add_propose_block(p_block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        c_block = CommitBlock()
        c_block.from_json(message_content['commit_data'])
        self.miner.blockchain.add_commit_block(c_block, message_content['previous']['depth'] + 1,
                                                p_block.hash(), p_block.pub_key)
        if c_block.malicious:
            msg = ', ' + str(c_block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg =  ', ' + str(c_block.weight)
            self.miner.res_loggerH.info(msg)

        # if cancel all and the non-malicious can find 2 blocks the malicious gives up
        print(message_content['previous']['depth'])
        print(self.miner.current_block[0] == 1)
        if self.cancel_all and (message_content['previous']['depth'] - self.miner.current_block[0] == 1):
            logging.info("LOSE: MALICIOUS LOST 2 - 0")
            print("give up")
            self.miner.current_block = (self.miner.current_block[0] + 1, self.miner.current_block[1])
            self.block_appeared = False
            self.restart()
            return

        if message_content['previous']['depth']+1 == self.miner.depth_cancel_block and not c_block.malicious or \
                     (self.cancel_all and not c_block.malicious and
                     message_content['previous']['depth'] == self.miner.current_block[0]):  # here the previous is the last commit
            self.block_appeared = True
            if self.i_should_propose:
                self.i_should_propose = False
                self.timestamp = None
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
                self.miner.broadcast.broadcast(json.dumps(message), PROPOSAL_COMMIT_TAG)
                if self.cancel_all and self.miner.current_block[0] % 2 == 1:
                    logging.info("LOSE: MALICIOUS LOST 2 - 1")
                    self.block_appeared = False
                self.restart()
            elif self.cancel_all and self.miner.current_block[0] % 2 == 1:
                logging.info("LOSE: MALICIOUS LOST 2 - 1")
                self.block_appeared = False
                self.restart()

        # We only need this condition if SWITCH_TH != 0
        # if message_content['previous']['hash'] == self.miner.current_block[1].hash() and c_block.malicious:
        #     self.restart()
        # FIXME should the upper part only restart or do something else?
        if c_block.weight - self.miner.current_block[1].weight > SWITCH_TH:
            if c_block.malicious or message_content['previous']['depth'] + 1 < self.miner.depth_cancel_block:
                if self.cancel_all and self.miner.current_block[0] % 2 == 1:
                    self.block_appeared = False
                self.restart()


class Mining(State):
    def __init__(self, miner):
        logging.info("MINING state")
        super(Mining, self).__init__(miner)
        self.miner.transaction_list = []
        self.miner.nonce_list = []
        #we use "already found" to keep track of the ongoing reinforcements
        self.miner.already_found = 0

    #Every miner is sending his RF value so that all others know the sum of the current found RFs
    #Info about found RFs is received
    def reinforcement_info_process(self, value, sign):
        message_content = json.loads(value)
        if message_content['hash'] == self.miner.current_block[1].hash():
            if check_hash(self.miner.current_block[1], message_content['nonce'],
                          RSA.import_key(message_content['pub_key']), REINF_TH):
                self.miner.already_found += min(1, COMMIT_TH/\
                                      int(compute_hash(self.miner.current_block[1].hash(hex=False),
                                                       message_content['nonce'],
                                                       RSA.import_key(message_content['pub_key']).exportKey('DER')), 16))
                if self.miner.current_block[1].malicious:
                    msg = ', ' + str(self.miner.current_block[1].weight + self.miner.already_found )
                    self.miner.res_loggerM.info(msg)
                else:
                    msg = ', ' + str(self.miner.current_block[1].weight + self.miner.already_found)
                    self.miner.res_loggerH.info(msg)

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        #print("IN HASH FRESH MINING")
        #print("current_block[1].hash()")
        #print(self.miner.current_block[1].hash(hex=True))
        #print("get_last.hash()")
        #print(self.miner.blockchain.get_last()[1].hash(hex=True))
        #print("current_block[1].prev_link.hash()")
        #print(self.miner.current_block[1].prev_link.hash(hex=True))
        return hash_value == value

    def hash_value_process(self, value, nonce):
        #value is the found hash value
        if self.is_hash_fresh(value, nonce):
            if int(value, 16) < COMMIT_TH:
                #if it is small enough to append a new block
                logging.info("hash found")
                print("Hash found")
                #we don't stop the mining because we want to use the time before a commit
                #  to find as much reinforcements as possible
                #self.miner.stop_mining.set_stop()
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
                #otherwise use it as reinforcement(just send the info about it, RFs are sent when propose block appears)
                logging.info("RF found")
                self.miner.nonce_list.append(nonce)
                message = {}
                message['hash'] = self.miner.current_block[1].hash()
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                message['nonce'] = nonce
                self.miner.already_found += min(1, COMMIT_TH / \
                                      int(compute_hash(self.miner.current_block[1].hash(hex=False),
                                                       nonce,
                                                       self.miner.public_key.exportKey('DER')), 16))
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_INF_TAG)

    def proposal_process(self, value):
        print("Proposal was received")
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.miner.current_block = (message_content['previous']['depth']+1, block)
            # we don't stop the mining because we want to use the time before a commit
            #  to find as much reinfocements as possible
            #self.miner.stop()
            self.miner.state = ReinforcementSent(self.miner)
            if len(self.miner.nonce_list) > 0:
                logging.info("RFs > 0 ")
                message = {}
                message['nonce_list'] = list(self.miner.nonce_list)
                message['hash'] = self.miner.current_block[1].hash() #hash of the new proposed block
                message['hash_commit'] = message_content['previous']['hash'] #hash of the block on top of which it was mined
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
        if block.malicious:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerH.info(msg)
        if block.weight - (self.miner.current_block[1].weight + self.miner.already_found) > SWITCH_TH:
            logging.info("Switching branch - my current block was: %s", \
                         self.miner.current_block[1].weight + self.miner.already_found)
            self.miner.stop_mining.set_stop()
            self.miner.transaction_list = []
            self.miner.nonce_list = []
            self.miner.already_found = 0
            self.miner.stop()
            self.miner.start_new_mining()
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.miner.current_block = (message_content['previous']['depth'], block)

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
        #we use the timestamp to know which malicious miner found a block first
        self.timestamp = None
        self.nonce = None   # the nonce the miner will use when proposing the malicious block
        self.block_appeared = False #???
        if self.miner.depth_cancel_block == -1:
            self.cancel_all = True
        else:
            self.cancel_all = False
        print("MINING MALICIOUS")

    def restart(self):
        self.miner.stop()
        self.miner.transaction_list = []
        self.miner.nonce_list = []
        self.i_should_propose = False
        self.timestamp = None
        self.nonce = None
        self.block_appeared = False
        if self.miner.depth_cancel_block == -1:
            self.cancel_all = True

        else:
            self.cancel_all = False
        self.miner.start_new_mining()

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    #Some other malicious miner found a small enough hash and sends a mal propose agreement
    def malicious_proposal_agreement_process(self, value):
        message_content = json.loads(value)
        if message_content['depth'] == self.miner.current_block[0]:
            if self.timestamp is None or message_content['timestamp'] < self.timestamp:
                self.timestamp = message_content['timestamp']
                self.i_should_propose = False
                if self.nonce is not None:
                    self.miner.nonce_list.append(self.nonce)

    def hash_value_process(self, value, nonce):
        #if the mining depth is greater than the cancel_block depth -1 --> always true for the cancel all strategy
        if self.is_hash_fresh(value, nonce) and self.miner.current_block[0] >= self.miner.depth_cancel_block - 1:
            #if timestamp is None --> no other malicious miner has proposed
            #and hash value small enough to propose
            if int(value, 16) < COMMIT_TH and self.timestamp is None:
                logging.info("hash found")
                print("hash found")
                #if the honest block we are waiting for hasn't appeared yet
                if not self.block_appeared:
                    ts = int(time())
                    my_prop = {
                        'timestamp': ts,
                        'depth': self.miner.current_block[0],
                        'pub_key': self.miner.public_key.exportKey('PEM').decode()
                    }
                    self.timestamp = ts
                    self.nonce = nonce
                    self.i_should_propose = True
                    self.miner.broadcast.broadcast(json.dumps(my_prop), MALICIOUS_PROPOSAL_AGREEMENT_TAG)
                else:
                    #the honest block we're waiting for has already appeared
                    # we don't stop the mining because we want to use the time before a commit
                    #  to find as much reinforcements as possible
                    #self.miner.stop_mining.set_stop()
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
            else:
                self.miner.nonce_list.append(nonce)

    def proposal_process(self, value):
        print("Proposal was received")
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        #add(block, depth, hash value)
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])
        #current_block[0] = depth ; current_block[1]=block
        #if the received block was mined on top of the one we are mining
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            if block.malicious:
                # we don't stop the mining because we want to use the time before a commit
                #  to find as much reinforcements as possible
                #self.miner.stop_mining.set_stop()
                self.miner.current_block = (message_content['previous']['depth'] + 1, block)
                self.miner.state = ReinforcementSent(self.miner)
                print("Switch to reinforcement sent")
                if len(self.miner.nonce_list) > 0:
                    message = {}
                    message['nonce_list'] = list(self.miner.nonce_list)
                    message['hash'] = self.miner.current_block[1].hash()
                    message['hash_commit'] = message_content['previous']['hash']
                    message['depth'] = self.miner.current_block[0]
                    message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                    self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)

    def commit_process(self, value):
        print("Commit was received")
        self.miner.reinforcement_pom.check_reinforcements_commit(value)
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'], message_content['pub_key'])
        if block.malicious:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg =  ', ' + str(block.weight)
            self.miner.res_loggerH.info(msg)
        if (block.malicious and block.weight - self.miner.current_block[1].weight > SWITCH_TH) or \
                (message_content['previous']['depth'] < self.miner.depth_cancel_block):
            self.restart()
            #self.miner.stop()
            #self.miner.transaction_list = []
            #self.miner.nonce_list = []
            #self.miner.start_new_mining()
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.miner.current_block = (message_content['previous']['depth'], block)

        #if the depth of the received block is same as the cancel block depth and
        elif (message_content['previous']['depth'] == self.miner.depth_cancel_block and not block.malicious) or \
                (self.cancel_all and not block.malicious and
                message_content["hash_last_commit"] == self.miner.current_block[1].hash()): # here the previous is the propose block
            #????if it is cancel_all then we should mark it as block appeared
            if not self.cancel_all:
                self.block_appeared = True
                #perhaps should be done sooner than when receiving a commit block
            if self.i_should_propose:
                self.i_should_propose = False
                self.timestamp = None
                self.miner.stop_mining.set_stop()
                block = ProposeBlock(self.nonce, self.miner.public_key.exportKey('PEM').decode(),
                                     list(self.miner.transaction_list))
                self.nonce = None
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
            # the malicious give up if no hash was found by the moment the honest guys commit
            elif self.cancel_all and self.timestamp is None:
                self.miner.stop_mining.set_stop()
                self.miner.transaction_list = []
                self.miner.nonce_list = []
                self.miner.start_new_mining()
        # this condition is necessary if the honest and malicious are not mining on top of the same block and avoids the
        # malicious miners of being stuck
        # this happens in the following situation:
        # ## both are mining on top of A:
        # ## malicious find a good hash and keep it behing their back
        # ## honest broadcast P1 and C1 on top of A
        # ## malicious broadcast P1'
        # ## honest broadcast P2 on top of C1 and change to Reinforcement Sent/Collecting state
        # ## malicious broadcast C1' which is heavier than C1 and start mining on top of it
        # ## the honest are in Reinforcement Sent/Collecting so they do not switch branches immediately
        # ## honest broadcast C2 on top of P3, which is heavier than C1' so they mine on top of it
        # at this point the malicious miners are waiting for some block with the previous hash equal to C1' to broadcast
        # what they have found but this never happens, because the honest are on a different branch
        elif self.cancel_all and not block.malicious and \
            message_content['previous']['depth'] > self.miner.current_block[0]:
            logging.info("Synchronizing branches")
            self.nonce = None
            self.timestamp = None
            self.block_appeared = False
            self.i_should_propose = False
            self.miner.stop()
            self.miner.transaction_list = []
            self.miner.nonce_list = []
            self.miner.start_new_mining()

    def reinforcement_process(self, value, sign):
        print("Reinforcement was received")
        self.miner.reinforcement_pom.new_reinforcement(value, sign)


class ReinforcementSent(State):
    def __init__(self, miner):
        logging.info("REINFORCEMENT SENT state")
        super(ReinforcementSent, self).__init__(miner)
        reactor.suggestThreadPoolSize(30)
        self.timeout = reactor.callLater(COMMIT_TIMEOUT, self.mining_switch)

    def mining_switch(self):
        if self.miner.malicious:
            self.miner.state = MaliciousMining(self.miner)
            if self.miner.depth_cancel_block != -1:
                self.miner.state.block_appeared = True
        else:
            self.miner.state = Mining(self.miner)
        self.miner.stop()
        prev_block = self.miner.current_block[1].prev_link
        self.miner.current_block = (self.miner.current_block[0]-1, prev_block)
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
        if block.malicious:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerH.info(msg)
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.miner.current_block = (message_content['previous']['depth'], block)
            if self.miner.malicious:
                self.miner.state = MaliciousMining(self.miner)
                if self.miner.depth_cancel_block != -1:
                    self.miner.state.block_appeared = True
            else:
                self.miner.state = Mining(self.miner)
            self.miner.stop()
            self.miner.start_new_mining()
            print("Switch to mining")

    def reinforcement_process(self, value, sign):
        print("Reinforcement was received")
        self.miner.reinforcement_pom.new_reinforcement(value, sign)

    def reinforcement_info_process(self, value, sign):
        message_content = json.loads(value)
        if(not self.miner.malicious):
            if message_content['hash'] == self.miner.blockchain.get_last()[1].hash():
                if check_hash(self.miner.blockchain.get_last()[1], message_content['nonce'],
                          RSA.import_key(message_content['pub_key']), REINF_TH):
                    self.miner.already_found += min(1, COMMIT_TH/\
                                      int(compute_hash(self.miner.blockchain.get_last()[1].hash(hex=False),
                                                       message_content['nonce'],
                                                       RSA.import_key(message_content['pub_key']).exportKey('DER')), 16))
                    if self.miner.blockchain.get_last()[1].malicious:
                        msg = ', ' + str(self.miner.blockchain.get_last()[1].weight + self.miner.already_found)
                        self.miner.res_loggerM.info(msg)
                    else:
                        msg = ', ' + str(self.miner.blockchain.get_last()[1].weight + self.miner.already_found)
                        self.miner.res_loggerH.info(msg)
                
    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.blockchain.get_last()[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def is_hash_fresh_mal(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].prev_link.hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def hash_value_process(self, value, nonce):
        #value is the found hash value
        if (not self.miner.malicious):
            if self.is_hash_fresh(value, nonce):
                self.miner.nonce_list.append(nonce)
                message = {}
                message['hash'] = self.miner.blockchain.get_last()[1].hash()
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                message['nonce'] = nonce
                self.miner.already_found += min(1, COMMIT_TH / \
                                  int(compute_hash(self.miner.blockchain.get_last()[1].hash(hex=False),
                                                   nonce,
                                                   self.miner.public_key.exportKey('DER')), 16))

                print("Sent Additional reinforcement info")
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_INF_TAG)

                message = {}
                nonce_list = []
                nonce_list.append(nonce)
                message['nonce_list'] = list(nonce_list)
                #current block is the propose that was last received
                message['hash'] = self.miner.current_block[1].hash()
                message['hash_commit'] = self.miner.blockchain.get_last()[1].hash(hex=True)
                message['depth'] = self.miner.current_block[0]
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                print("Sent Additional reinforcement")
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)
        else:
            if self.is_hash_fresh_mal(value, nonce):
                print("In hash fresh mal")
                self.miner.nonce_list.append(nonce)
                message = {}
                nonce_list = []
                nonce_list.append(nonce)
                message['nonce_list'] = list(nonce_list)
                #hash of the already appended propose block
                message['hash'] = self.miner.current_block[1].hash()
                #it is the hash of the last commit block
                message['hash_commit'] = self.miner.current_block[1].prev_link.hash(hex=True)
                #blockchain.get_last()[1].hash(hex=True)
                message['depth'] = self.miner.current_block[0]
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                print("Sent Additional Mal reinforcement")
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)




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
        reactor.suggestThreadPoolSize(30)
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
        message['previous']['hash'] = self.miner.current_block[1].hash()
        message['previous']['depth'] = self.miner.current_block[0]
        message['hash_last_commit'] = self.miner.current_block[1].prev_link.hash()
        message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
        logging.info("commit with %d reinforcements", len(self.received_reinforcements))
        self.miner.blockchain.add_commit_block(block, self.miner.current_block[0], self.miner.current_block[1].hash(),
                                               self.miner.public_key.exportKey('PEM').decode())
        if block.malicious:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerH.info(msg)
        if self.miner.malicious:
            self.miner.state = MaliciousMining(self.miner)
            if self.miner.depth_cancel_block != -1:
                self.miner.state.block_appeared = True
        else:
            self.miner.state = Mining(self.miner)
        self.miner.current_block = (message['previous']['depth'], block)
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
        else:
            logging.warning("W: received reinforcement for %s instead of %s", message_content['hash'][:10],
                            self.miner.current_block[1].hash()[:10])

    def commit_process(self, value):
        print("Commit was received")
        self.miner.reinforcement_pom.check_reinforcements_commit(value)
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'], message_content['pub_key'])
        if block.malicious:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerM.info(msg)
        else:
            msg = ', ' + str(block.weight)
            self.miner.res_loggerH.info(msg)

    def reinforcement_info_process(self, value, sign):
        if (not self.miner.malicious):
            message_content = json.loads(value)
            if message_content['hash'] == self.miner.blockchain.get_last()[1].hash():
                if check_hash(self.miner.blockchain.get_last()[1], message_content['nonce'],
                              RSA.import_key(message_content['pub_key']), REINF_TH):
                    self.miner.already_found += min(1, COMMIT_TH/\
                                          int(compute_hash(self.miner.blockchain.get_last()[1].hash(hex=False),
                                                       message_content['nonce'],
                                                       RSA.import_key(message_content['pub_key']).exportKey('DER')), 16))
                    if self.miner.blockchain.get_last()[1].malicious:
                        msg = ', ' + str(self.miner.blockchain.get_last()[1].weight + self.miner.already_found)
                        self.miner.res_loggerM.info(msg)
                    else:
                        msg = ', ' + str(self.miner.blockchain.get_last()[1].weight + self.miner.already_found)
                        self.miner.res_loggerH.info(msg)

    def is_hash_fresh(self, value, nonce):
        hash_value = compute_hash(self.miner.blockchain.get_last()[1].hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def is_hash_fresh_mal(self, value, nonce):
        hash_value = compute_hash(self.miner.current_block[1].prev_link.hash(hex=False),
                                  nonce, self.miner.public_key.exportKey('DER'))
        return hash_value == value

    def hash_value_process(self, value, nonce):
        #value is the found hash value
        if (not self.miner.malicious):
            if self.is_hash_fresh(value, nonce):
                self.miner.nonce_list.append(nonce)
                message = {}
                message['hash'] = self.miner.blockchain.get_last()[1].hash()
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                message['nonce'] = nonce
                self.miner.already_found += min(1, COMMIT_TH / \
                                      int(compute_hash(self.miner.blockchain.get_last()[1].hash(hex=False),
                                                       nonce,
                                                       self.miner.public_key.exportKey('DER')), 16))
                print("Sent Additional reinforcement info")
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_INF_TAG)

                message = {}
                nonce_list = []
                nonce_list.append(nonce)
                message['nonce_list'] = list(nonce_list)
                message['hash'] = self.miner.current_block[1].hash()
                message['hash_commit'] = self.miner.blockchain.get_last()[1].hash(hex=True)
                message['depth'] = self.miner.current_block[0]
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                print("Sent Additional reinforcement")
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)
        else:
            if self.is_hash_fresh_mal(value, nonce):
                print("In hash fresh mal")
                self.miner.nonce_list.append(nonce)
                message = {}
                nonce_list = []
                nonce_list.append(nonce)
                message['nonce_list'] = list(nonce_list)
                #hash of the already appended propose block
                message['hash'] = self.miner.current_block[1].hash()
                #it is the hash of the last commit block
                message['hash_commit'] = self.miner.current_block[1].prev_link.hash(hex=True)
                #blockchain.get_last()[1].hash(hex=True)
                message['depth'] = self.miner.current_block[0]
                message['pub_key'] = self.miner.public_key.exportKey('PEM').decode()
                print("Sent Additional Mal reinforcement")
                self.miner.broadcast.broadcast(json.dumps(message), REINFORCEMENT_TAG)

