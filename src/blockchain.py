import json
import hashlib
from Crypto.PublicKey import RSA
from constants import COMMIT_TH, REINF_TH
from hash import compute_hash, check_hash
import time

class Blockchain:
    def __init__(self):
        self.position_index = []
        self.list_of_leaves = []
        self.head = ProposeBlock(0)
        self.position_index.append([])
        self.position_index[0].append(self.head)
        self.head.commit_link = CommitBlock({})
        self.head.commit_link.propose_link = self.head
        self.position_index.append([])
        self.position_index[1].append(self.head.commit_link)
        self.list_of_leaves.append((1, self.head.commit_link))
        self.pool_of_blocks = {}

    def get_last(self, mal_flag=False):
        max_w = -1
        last_block = None
        max_w_mal = -1
        last_block_mal = None
        depth = 0
        depth_mal = 0
        for d, block in self.list_of_leaves:
            if block.weight > max_w:
                max_w = block.weight
                last_block = block
                depth = d
            if mal_flag:
                if block.malicious:
                    if block.weight > max_w_mal:
                        max_w_mal = block.weight
                        last_block_mal = block
                        depth_mal = d

        if last_block_mal is None:
            return depth, last_block
        else:
            return depth_mal, last_block_mal


    def add_propose_block(self, block, depth, hash_value):
        node = self.find_position(depth, hash_value)
        if node is not None:
            if not check_hash(node, block.nonce, RSA.import_key(block.pub_key), COMMIT_TH):
                print("Malicious propose")
                return
            node.next_links.append(block)
            block.prev_link = node
            if len(self.position_index) == depth + 1:
                self.position_index.append([])
            self.position_index[depth + 1].append(block)
            if node.malicious:
                block.malicious = True
            # find and append next blocks
            if (depth+1) in self.pool_of_blocks.keys():
                for h, b, pub_key in self.pool_of_blocks[depth+1]:
                    if block.hash() == h:
                        self.add_commit_block(b, depth+1, h, pub_key)
                        self.pool_of_blocks[depth + 1].remove((h, b))
        else:
            if depth not in self.pool_of_blocks.keys():
                self.pool_of_blocks[depth] = []
            self.pool_of_blocks[depth].append((hash_value, block))

    def add_commit_block(self, block, depth, hash_value, pub_key):
        node = self.find_position(depth, hash_value)
        if node is not None:
            if pub_key != node.pub_key:
                print("Impersonated commit")
                return
            for k in block.reinforcements.keys():
                for nonce in block.reinforcements[k]['nonces']:
                    if not check_hash(node.prev_link, nonce, RSA.import_key(k), REINF_TH):
                        print("Malicious commit")
                        return
            node.commit_link = block
            block.propose_link = node
            if len(self.position_index) == depth+1:
                self.position_index.append([])
            self.position_index[depth+1].append(block)
            previous_commit = node.prev_link
            if node.malicious:
                block.malicious = True
            for d, b in self.list_of_leaves:
                if previous_commit == b:
                    self.list_of_leaves.remove((d, b))
            self.list_of_leaves.append((depth+1, block))
            block.weight = previous_commit.weight+self.calculate_weight(node, block, previous_commit)
            #print(block.weight)
            #find and append next blocks
            if (depth+1) in self.pool_of_blocks.keys():
                for h, b in self.pool_of_blocks[depth + 1]:
                    if block.hash() == h:
                        self.add_propose_block(b, depth + 1, h)
                        self.pool_of_blocks[depth + 1].remove((h, b))
        else:
            if depth not in self.pool_of_blocks.keys():
                self.pool_of_blocks[depth] = []
            self.pool_of_blocks[depth].append((hash_value, block, pub_key))

    def calculate_weight(self, propose, commit, previous_commit):
        sum = COMMIT_TH/int(compute_hash(previous_commit.hash(hex=False), propose.nonce,
                                              RSA.import_key(propose.pub_key).exportKey('DER')), 16)
        #print('propose:', sum)
        for k in commit.reinforcements.keys():
            for nonce in commit.reinforcements[k]['nonces']:
                sum += COMMIT_TH/int(compute_hash(previous_commit.hash(hex=False), nonce,
                                                  RSA.import_key(k).exportKey('DER')), 16)
        #print('propose+commit:', sum)
        return sum

    def find_position(self, depth, hash_value):
        if depth < len(self.position_index):
            for block in self.position_index[depth]:
                if block.hash() == hash_value:
                    return block
        return None


class ProposeBlock:
    def __init__(self, nonce=0, _id="0", tr_list=[]):
        self.nonce = nonce
        self.pub_key = _id
        self.transaction_list = tr_list
        self.prev_link = None
        self.commit_link = None
        self.malicious = False
        self.ts = int(time.time())

    def from_json(self, json_str):
        data = json.loads(json_str)
        self.nonce = data['nonce']
        self.pub_key = data['pub_key']
        self.transaction_list = data['transaction_list']
        self.ts = data['ts']
        self.malicious = data['malicious']

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
        data['ts'] = self.ts
        data['malicious'] = self.malicious
        return json.dumps(data, sort_keys=True)


class CommitBlock:
    def __init__(self, reinf_list={}, poms=list()):
        self.reinforcements = reinf_list
        self.malicious = False
        self.poms = poms
        self.propose_link = None
        self.next_links = []
        self.weight = 0
        self.ts = int(time.time())

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
        self.poms = data['poms']
        self.malicious = data['malicious']
        self.ts = data['ts']

    def get_json(self):
        data = {}
        data['reinforcements'] = self.reinforcements
        data['poms'] = self.poms
        data['malicious'] = self.malicious
        data['ts'] = self.ts
        return json.dumps(data, sort_keys=True)
