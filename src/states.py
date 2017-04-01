import hashlib
import json
from blockchain import CommitBlock, ProposeBlock
from twisted.internet import reactor
#58
VALUE_TH = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


class State:
    def __init__(self, miner):
        self.miner=miner

    def hash_value_process(self, value, nonce):
        pass

    def message_process(self, type, value):
        pass

    def proposal_process(self, value):
        pass

    def reinforcement_process(self, value):
        pass

    def commit_process(self, value):
        pass

    def transaction_process(self, value):
        self.miner.transaction_list.append(value)


class Mining(State):
    def __init__(self, miner):
        super(Mining, self).__init__(miner)
        self.miner.transaction_list = []
        self.miner.nonce_list = []
        #print("MINING")

    def is_hash_fresh(self, value, nonce):
        hash_function = hashlib.sha256()
        hash_function.update(self.miner.current_block[1].hash(hex=False))
        hash_function.update(self.miner.id.to_bytes(16, byteorder='big'))
        hash_function.update(nonce.to_bytes(16, byteorder='big'))
        hash_value = hash_function.hexdigest()
        return hash_value == value

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce):
            if int(value, 16) <= VALUE_TH:
                print("Hash found")
                self.miner.stop_mining.set_stop()
                block = ProposeBlock(int(value, 16), self.miner.id, list(self.miner.transaction_list))
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
                self.miner.nonce_list.append(value)

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
            message = {}
            message['nonce_list'] = list(self.miner.nonce_list)
            # FIXME in the future, do not send reinforcement if the list is empty
            message['hash'] = self.miner.current_block[1].hash()
            self.miner.broadcast.broadcast(json.dumps(message), "reinforcement")
            print("Switch to reinforcement sent")

    def commit_process(self, value):
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'])


class ReinforcementSent(State):
    def __init__(self, miner):
        super(ReinforcementSent, self).__init__(miner)
        #print("REINF_SENT")

    def proposal_process(self, value):
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])

    def commit_process(self, value):
        print("Commit was received")
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'])
        if message_content['previous']['hash'] == self.miner.current_block[1].hash():
            self.miner.state = Mining(self.miner)
            self.miner.start_new_mining()
            print("Switch to mining")


class ReinforcementCollecting(State):
    def __init__(self, miner):
        super(ReinforcementCollecting, self).__init__(miner)
        #print("REINF_COLLECTING")
        message = {}
        message['nonce_list'] = []
        message['hash'] = self.miner.current_block[1].hash()
        self.timeout = reactor.callLater(3, self.reinforcement_process, json.dumps(message))

    def proposal_process(self, value):
        message_content = json.loads(value)
        block = ProposeBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_propose_block(block, message_content['previous']['depth'],
                                                message_content['previous']['hash'])

    def reinforcement_process(self, value):
        if self.timeout.active():
            print("Reinforcement was received")
            self.timeout.cancel()
        else:
            print("Reinforcement was not received")
        message_content = json.loads(value)
        if message_content['hash'] == self.miner.current_block[1].hash():
            block = CommitBlock(message_content['nonce_list'])
            message = {}
            message['previous'] = {}
            message['data'] = block.get_json()
            message['previous']['hash'] = self.miner.current_block[1].hash()
            message['previous']['depth'] = self.miner.current_block[0]
            self.miner.blockchain.add_commit_block(block, self.miner.current_block[0], self.miner.current_block[1].hash())
            self.miner.state = Mining(self.miner)
            self.miner.start_new_mining()
            self.miner.broadcast.broadcast(json.dumps(message), "commit")
            print("Switch to mining")

    def commit_process(self, value):
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        self.miner.blockchain.add_commit_block(block, message_content['previous']['depth'],
                                               message_content['previous']['hash'])
