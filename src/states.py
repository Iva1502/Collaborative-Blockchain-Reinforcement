import hashlib
#57
VALUE_TH = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
PROPOSAL = "proposal"
REINFORCEMENT = "reinforcement"
COMMIT = "commit"


class State:
    def __init__(self, miner):
        self.miner=miner

    def hash_value_process(self, value, nonce):
        pass

    def message_process(self, type, value):
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
                #self.miner.state = Reinf_collecting(self.miner)
                #self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)
            else:
                self.miner.nonce_list.append(value)

    def message_process(self, type, value):
        if type == PROPOSAL:
            self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)
            if value.hash == hash(self.miner.current_block[1]):
                self.miner.current_block = (value.data, value.data)
                self.miner.stop_mining.stop()
                self.miner.state = Reinf_sending(self.miner)
                self.miner.broadcast.broadcast(REINFORCEMENT, self.miner.nonce_list)

        if type == COMMIT:
            self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)


class Reinf_sending(State):
    def __init__(self, miner):
        super(Reinf_sending, self).__init__(miner)

    def message_process(self, type, value):
        if type == "proposal":
            self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)

        if type == "commit":
            self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)
            if value.hash == hash(self.miner.current_block[1]):
                self.miner.state = Mining(self.miner)
                self.miner.start_new_mining()


class Reinf_collecting(State):
    def __init__(self, miner):
        super(Reinf_collecting, self).__init__(miner)

    def message_process(self, type, value):
        if type == "proposal":
            self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)

        if type == "reinforcement":
            if value.hash == hash(self.miner.current_block[1]):
                self.miner.current_block.append(value)
                self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)
                self.miner.state = Mining(self.miner)
                self.miner.start_new_mining()
                self.miner.broadcast.broadcast("commit")

        if type == "commit":
            self.miner.blockchain.add_commit_block(value.data, value.depth, value.hash)