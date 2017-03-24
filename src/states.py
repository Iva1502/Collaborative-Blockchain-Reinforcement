VALUE_TH = 1e-8


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

    def hash_value_process(self, value, nonce):
        if value.block == self.miner.current_block:
            if value <= VALUE_TH:
                self.miner.stop_mining.stop()
                self.miner.state = Reinf_collecting(self.miner)
                self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)
                self.miner.broadcast.broadcast("proposal")
            else:
                self.miner.nonce_list.append(value)

    def message_process(self, type, value):
        if type == "proposal":
            self.miner.blockchain.add_propose_block(value.data, value.depth, value.hash)
            if value.hash == hash(self.miner.current_block[1]):
                self.miner.current_block = (value.data, value.data)
                self.miner.stop_mining.stop()
                self.miner.state = Reinf_sending(self.miner)
                self.miner.broadcast.broadcast("reinforcement", self.miner.nonce_list)

        if type == "commit":
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