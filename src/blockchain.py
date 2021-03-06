import json
import hashlib
from Crypto.PublicKey import RSA
from constants import COMMIT_TH, REINF_TH, CANCEL_PARTICULAR_BLOCK_TH
from hash import compute_hash, check_hash
import time
import logging


class Blockchain:
    def __init__(self, genesis_time, pure=False, copy_mal_flag=True):
        # position_index array contains a tuple (Propose Block, Commit Block) for each depth
        self.position_index = []
        # list_of_leaves array contains tuples (depth, Commit block)
        self.list_of_leaves = []
        self.head = ProposeBlock(genesis_time=genesis_time)
        self.position_index.append([])
        self.position_index[0].append(self.head)
        self.head.commit_link = CommitBlock(genesis_time=genesis_time)
        self.head.commit_link.propose_link = self.head
        self.position_index[0].append(self.head.commit_link)
        self.list_of_leaves.append((0, self.head.commit_link))
        self.pool_of_blocks = {}
        self.pure = pure
        self.copy_mal_flag = copy_mal_flag
        #??? copy_mal_flag ???
        # in Miner called like: copy_mal_flag = (depth_cancel_block != -1)
        # it means copy_mal_flag = false if the strategy is cancel_all_blocks

    def get_last(self, mal_flag=False, cancel_all=False, threshold_divisor=1):
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
                print(block.hash()[:10])
                if block.malicious:
                    if block.weight > max_w_mal:
                        max_w_mal = block.weight
                        last_block_mal = block
                        depth_mal = d

        if not cancel_all and mal_flag and last_block_mal is not None \
                and last_block.weight > last_block_mal.weight + int(CANCEL_PARTICULAR_BLOCK_TH / threshold_divisor):
            logging.info("END: HONEST WIN. %s against %s", last_block.weight,
                         last_block_mal.weight + CANCEL_PARTICULAR_BLOCK_TH / threshold_divisor)
            print("END: HONEST WIN %s against %s", last_block.weight,
                         last_block_mal.weight + CANCEL_PARTICULAR_BLOCK_TH / threshold_divisor)
            print('\a')
        if last_block_mal is None:
            print("return NOT malicious with depth: ")
            print(depth)
            return depth, last_block
        else:
            print("return malicious with depth: ")
            print(depth_mal)
            return depth_mal, last_block_mal

    def add_propose_block(self, block, depth, hash_value):
        node = self.find_position(depth, hash_value)
        if node is not None:
            if not check_hash(node, block.nonce, RSA.import_key(block.pub_key), COMMIT_TH):
                logging.info("malicious propose")
                print("Malicious propose")
                return
            node.next_links.append(block)
            block.prev_link = node
            if len(self.position_index) == depth + 1:
                self.position_index.append([])
            self.position_index[depth + 1].append(block)
            if self.copy_mal_flag:
                if node.malicious:
                    block.malicious = True
            if block.malicious:
                logging.info("appended malicious propose %s on top of %s", block.hash()[:10], hash_value[:10])
            else:
                logging.info("appended honest propose %s on top of %s", block.hash()[:10], hash_value[:10])
            # find and append next blocks
            if (depth+1) in self.pool_of_blocks.keys():
                for h, b, pub_key in self.pool_of_blocks[depth+1]:
                    if block.hash() == h:
                        self.add_commit_block(b, depth+1, h, pub_key)
                        self.pool_of_blocks[depth + 1].remove((h, b, pub_key))
        else:
            if depth not in self.pool_of_blocks.keys():
                self.pool_of_blocks[depth] = []
            self.pool_of_blocks[depth].append((hash_value, block))

    def add_commit_block(self, block, depth, hash_value, pub_key):
        node = self.find_position(depth, hash_value)
        if node is not None:
            if pub_key != node.pub_key:
                logging.info("impersonated commit")
                print("Impersonated commit")
                return
            for k in block.reinforcements.keys():
                for nonce in block.reinforcements[k]['nonces']:
                    if not check_hash(node.prev_link, nonce, RSA.import_key(k), REINF_TH):
                        logging.info("malicious commit")
                        print("Malicious commit")
                        return
            node.commit_link = block
            block.propose_link = node
            self.position_index[depth].append(block)
            previous_commit = node.prev_link
            if self.copy_mal_flag:
                if node.malicious:
                    block.malicious = True
            if block.malicious:
                logging.info("appended malicious commit %s on top of %s", block.hash()[:10], hash_value[:10])
            else:
                logging.info("appended honest commit %s on top of %s", block.hash()[:10], hash_value[:10])
            for d, b in self.list_of_leaves:
                if previous_commit == b:
                    self.list_of_leaves.remove((d, b))
            self.list_of_leaves.append((depth, block))
            if self.pure:
                block.weight = previous_commit.weight + 1
            else:
                block.weight = previous_commit.weight + self.calculate_weight(node, block, previous_commit)
            logging.info("weight: %s", str(block.weight))
            print("weight: " + str(block.weight))
            #find and append next blocks
            if (depth) in self.pool_of_blocks.keys():
                for h, b in self.pool_of_blocks[depth]:
                    if block.hash() == h:
                        self.add_propose_block(b, depth, h)
                        self.pool_of_blocks[depth].remove((h, b))
        else:
            if depth not in self.pool_of_blocks.keys():
                self.pool_of_blocks[depth] = []
            self.pool_of_blocks[depth].append((hash_value, block, pub_key))
    '''
    def calculate_weight(self, propose, commit, previous_commit):
        sum = COMMIT_TH/int(compute_hash(previous_commit.hash(hex=False), propose.nonce,
                                              RSA.import_key(propose.pub_key).exportKey('DER')), 16)
        for k in commit.reinforcements.keys():
            for nonce in commit.reinforcements[k]['nonces']:
                sum += COMMIT_TH/int(compute_hash(previous_commit.hash(hex=False), nonce,
                                                  RSA.import_key(k).exportKey('DER')), 16)
        return sum
    '''


    def calculate_weight(self, propose, commit, previous_commit):
        sum = 1 #min(1, COMMIT_TH/int(compute_hash(previous_commit.hash(hex=False), propose.nonce,
                                              #RSA.import_key(propose.pub_key).exportKey('DER')), 16))
        num_rfs = 0
        for k in commit.reinforcements.keys():
            for nonce in commit.reinforcements[k]['nonces']:
                sum += min(1, COMMIT_TH/int(compute_hash(previous_commit.hash(hex=False), nonce,
                                                  RSA.import_key(k).exportKey('DER')), 16))
                num_rfs +=1
        w = sum + previous_commit.weight
        logging.info("Weight: %s #RFs %s", w, num_rfs)
        return sum

    def find_position(self, depth, hash_value):
        if depth < len(self.position_index):
            for block in self.position_index[depth]:
                if block.hash() == hash_value:
                    return block
        return None

class ProposeBlock:
    def __init__(self, nonce=0, _id="0", tr_list=[], genesis_time=None):
        self.nonce = nonce
        self.pub_key = _id
        self.transaction_list = tr_list
        self.prev_link = None
        self.commit_link = None
        self.malicious = False
        if genesis_time is not None:
            self.ts = genesis_time
        else:
            self.ts = time.time()

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

    def print(self):
        print("Propose Block: malicious=" + str(self.malicious))


class CommitBlock:
    def __init__(self, reinf_list={}, poms=list(), genesis_time=None):
        self.reinforcements = reinf_list
        self.malicious = False
        self.poms = poms
        self.propose_link = None
        self.next_links = []
        self.weight = 0
        if genesis_time is not None:
            self.ts = genesis_time
        else:
            self.ts = time.time()

    def hash(self, hex=True):
        hash_function = hashlib.sha256()
        hash_function.update(self.get_json().encode())
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

    def print(self):
        print("Commit Block: malicious=" + str(self.malicious))
