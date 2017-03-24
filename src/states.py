import hashlib
#57
VALUE_TH = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


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
        pass


class Mining(State):
    def __init__(self, miner):
        super(Mining, self).__init__(miner)

    def is_hash_fresh(self, value, nonce):
        hash_function = hashlib.sha256()
        hash_function.update(self.miner.current_block[1].hash())
        hash_function.update(self.miner.id.to_bytes(16, byteorder='big'))
        hash_function.update(nonce.to_bytes(16, byteorder='big'))
        hash_value = hash_function.hexdigest()
        return hash_value == value

    def hash_value_process(self, value, nonce):
        if self.is_hash_fresh(value, nonce):
            if int(value, 16) <= VALUE_TH:
                self.miner.stop_mining.set_stop()
                self.miner.state = ReinforcementCollecting(self.miner)
                self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)
            else:
                self.miner.nonce_list.append(value)

    def proposal_process(self, value):
        self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)
        if value.hash == hash(self.miner.current_block[1]):
            self.miner.current_block = (value.data, value.data)
            self.miner.stop_mining.stop()
            self.miner.state = ReinforcementSent(self.miner)
            self.miner.broadcast.broadcast("reinforcement", self.miner.nonce_list)

    def commit_process(self, value):
        self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)

class ReinforcementSent(State):
    def __init__(self, miner):
        super(ReinforcementSent, self).__init__(miner)

    def proposal_process(self, value):
        self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)

    def commit_process(self, value):
        self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)
        if value.hash == hash(self.miner.current_block[1]):
            self.miner.state = Mining(self.miner)
            self.miner.start_new_mining()

class ReinforcementCollecting(State):
    def __init__(self, miner):
        super(ReinforcementCollecting, self).__init__(miner)

    def proposal_process(self, value):
        self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)

    def reinforcement_process(self, value):
        if value.hash == hash(self.miner.current_block[1]):
            self.miner.current_block.append(value)
            self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)
            self.miner.state = Mining(self.miner)
            self.miner.start_new_mining()
            self.miner.broadcast.broadcast("commit")

    def commit_process(self, value):
        self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)
