import json
import hashlib


class Blockchain:
    def __init__(self):
        self.position_index = []
        self.list_of_leaves = []
        self.head = ProposeBlock(0)
        self.position_index.append([])
        self.position_index[0].append(self.head)
        self.head.commit_link = CommitBlock([])
        self.head.commit_link.propose_link = self.head
        self.position_index.append([])
        self.position_index[1].append(self.head.commit_link)
        self.list_of_leaves.append((1, self.head.commit_link))

    def get_last(self):
        max_w = -1
        last_block = None
        depth = 0
        for d, block in self.list_of_leaves:
            if block.weight > max_w:
                max_w = block.weight
                last_block = block
                depth = d
        return depth, last_block

    def add_propose_block(self, block, depth, hash_value):
        node = self.find_position(depth, hash_value)
        if node is not None:
            node.next_links.append(block)
            block.prev_link = node
            if len(self.position_index) == depth + 1:
                self.position_index.append([])
            self.position_index[depth + 1].append(block)

    def add_commit_block(self, block, depth, hash_value):
        node = self.find_position(depth, hash_value)
        if node is not None:
            node.commit_link = block
            block.propose_link = node
            if len(self.position_index) == depth+1:
                self.position_index.append([])
            self.position_index[depth+1].append(block)
            previous_commit = node.prev_link
            for d, b in self.list_of_leaves:
                if previous_commit == b:
                    self.list_of_leaves.remove((d, b))
            self.list_of_leaves.append((depth+1, block))
            block.weight = previous_commit.weight+1

    def find_position(self, depth, hash_value):
        for block in self.position_index[depth]:
            if block.hash() == hash_value:
                return block
        return None


class ProposeBlock:
    def __init__(self, nonce=0, _id=None, tr_list=[]):
        self.nonce = nonce
        self.pub_key = _id
        self.transaction_list = tr_list
        self.prev_link = None
        self.commit_link = None

    def from_json(self, json_str):
        data = json.loads(json_str)
        self.nonce = data['nonce']
        self.pub_key = data['pub_key']
        self.transaction_list = data['transaction_list']

    def hash(self, hex=True):
        hash_function = hashlib.sha256()
        hash_function.update(self.get_json().encode())
        # compute the hash
        if hex:
            return hash_function.hexdigest()
        return hash_function.digest()

    def get_json(self):
        data = {}
        data['nonce'] = self.nonce
        data['pub_key'] = self.pub_key
        data['transaction_list'] = self.transaction_list
        return json.dumps(data, sort_keys=True)


class CommitBlock:
    def __init__(self, reinf_list=[]):
        self.reinforcements = reinf_list
        self.propose_link = None
        self.next_links = []
        self.weight = 0

    def hash(self, hex=True):
        hash_function = hashlib.sha256()
        hash_function.update(self.get_json().encode())
        # compute the hash
        if hex:
            return hash_function.hexdigest()
        return hash_function.digest()

    def from_json(self, json_str):
        data = json.loads(json_str)
        self.reinforcements = data['reinforcements']
        self.weight = data['weight']

    def get_json(self):
        data = {}
        data['reinforcements'] = self.reinforcements
        data['weight'] = self.weight
        return json.dumps(data, sort_keys=True)
