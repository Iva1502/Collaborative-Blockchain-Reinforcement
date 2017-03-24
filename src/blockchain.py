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
        return (depth, last_block)

    def add_propose_block(self, block, depth, hash):
        node = self.find_position(depth, hash)
        if node != None:
            node.next_links.append(block)
            block.prev_link = node
            if len(self.position_index) == depth + 1:
                self.position_index.append([])
            self.position_index[depth + 1].append(block)

    def add_commit_block(self, block, depth, hash):
        node = self.find_position(depth, hash)
        if node != None:
            node.commit_link = block
            block.propose_link = node
            if len(self.position_index) == depth+1:
                self.position_index.append([])
            self.position_index[depth+1].append(block)
            previous_commit = node.prev_link
            for d, b in self.list_of_leaves:
                if previous_commit == b:
                    self.list_of_leaves.remove((d,b))
            self.list_of_leaves.append((depth+1, block))
            block.weight = previous_commit.weight+1

    def find_position(self, depth, hash_value):
        for block in self.position_index[depth]:
            if hash(block) == hash_value:
                return block
        return None

class ProposeBlock:
    def __init__(self, nonce):
        self.nonce = nonce
        self.prev_link = None
        self.commit_link = None

    def hash(self):
        hash_function = hashlib.sha256()
        hash_function.update(self.get_json().encode())
        # compute the hash
        hash_value = hash_function.digest()
        return hash_value

    def get_json(self):
        data = {}
        data['nonce'] = self.nonce
        return json.dumps(data, sort_keys=True)


class CommitBlock:
    def __init__(self, reinf_list):
        self.reinforcements = reinf_list
        self.propose_link = None
        self.next_links = []
        self.weight = 0

    def hash(self):
        hash_function = hashlib.sha256()
        hash_function.update(self.get_json().encode())
        # compute the hash
        hash_value = hash_function.digest()
        return hash_value

    def get_json(self):
        data = {}
        data['reinforcements'] = self.reinforcements
        data['weight'] = self.weight
        return json.dumps(data, sort_keys=True)