import json
import hashlib
from Crypto.PublicKey import RSA
from constants import COMMIT_TH

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
        self.pool_of_blocks = {}

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
            # find and append next blocks
            if (depth+1) in self.pool_of_blocks.keys():
                for h, b in self.pool_of_blocks[depth+1]:
                    if block.hash() == h:
                        self.add_commit_block(b, depth+1, h)
                        self.pool_of_blocks[depth + 1].remove((h, b))
        else:
            if depth not in self.pool_of_blocks.keys():
                self.pool_of_blocks[depth] = []
            self.pool_of_blocks[depth].append((hash_value, block))

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
            block.weight = previous_commit.weight+self.calculate_weight(node, block, previous_commit)
            print(block.weight)
            #find and append next blocks
            if (depth+1) in self.pool_of_blocks.keys():
                for h, b in self.pool_of_blocks[depth + 1]:
                    if block.hash() == h:
                        self.add_propose_block(b, depth + 1, h)
                        self.pool_of_blocks[depth + 1].remove((h, b))
        else:
            if depth not in self.pool_of_blocks.keys():
                self.pool_of_blocks[depth] = []
            self.pool_of_blocks[depth].append((hash_value, block))

    def calculate_weight(self, propose, commit, previous_commit):
        sum = COMMIT_TH/self.hash_value(previous_commit, propose.nonce, propose.pub_key)
        for nonce in commit.reinforcements:
            sum += COMMIT_TH/self.hash_value(previous_commit, nonce, propose.pub_key)
        print(sum)
        return sum

    def hash_value(self, block, nonce, pub_key):
        hash_block = block.hash(hex=False)
        hash_function = hashlib.sha256()
        hash_function.update(hash_block)
        hash_function.update(RSA.import_key(pub_key).exportKey('DER'))
        hash_function.update(nonce.to_bytes(16, byteorder='big'))
        return int(hash_function.hexdigest(), 16)

    def find_position(self, depth, hash_value):
        if depth < len(self.position_index):
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
        #self.weight = data['weight']

    def get_json(self):
        data = {}
        data['reinforcements'] = self.reinforcements
        #data['weight'] = self.weight
        return json.dumps(data, sort_keys=True)
