import json
from blockchain import CommitBlock


class ReinforcementPOM:
    def __init__(self, miner):
        self.reinforcement_pool = {}
        self.miner = miner

    def new_reinforcement(self, value, signature):
        reinforcement_content = json.loads(value)
        nonce_list = reinforcement_content['nonce_list']
        hash_prop = reinforcement_content['hash']
        depth = reinforcement_content['depth']  # depth of the propose block
        pub_key = reinforcement_content['pub_key']
        hash_commit_block = self.miner.blockchain.find_position(depth, hash_prop).prev_link.hash()
        depth = self.miner.current_block[0]
        self.add_reinforcement(pub_key, depth, hash_commit_block, nonce_list, hash_prop, signature)

    def check_reinforcements_commit(self, value):
        message_content = json.loads(value)
        block = CommitBlock()
        block.from_json(message_content['data'])
        reinforcements = block.reinforcements
        for pub_key, dict_nonces_signature in reinforcements.items():
            depth_prop = message_content['previous']['depth']
            hash_prop = message_content['previous']['hash']
            hash_last_commit_block = self.miner.blockchain.find_position(depth_prop, hash_prop).prev_link.hash()
            self.add_reinforcement(pub_key, depth_prop, hash_last_commit_block, dict_nonces_signature['nonces'],
                                   depth_prop, dict_nonces_signature['signature'])

    def add_reinforcement(self, pub_key, depth, hash_commit_block, nonce_list, hash_prop, signature):
        content = (nonce_list, hash_prop, signature)
        if pub_key not in self.reinforcement_pool.keys():
            self.reinforcement_pool[pub_key] = {}
        if depth not in self.reinforcement_pool[pub_key].keys():
            self.reinforcement_pool[pub_key][depth] = {}
        if hash_commit_block not in self.reinforcement_pool[pub_key][depth].keys():
            self.reinforcement_pool[pub_key][depth][hash_commit_block] = []
        if content not in self.reinforcement_pool[pub_key][depth][hash_commit_block]:
            self.reinforcement_pool[pub_key][depth][hash_commit_block].append(content)
        self.search_pom(pub_key, depth, hash_commit_block, nonce_list, hash_prop)
        self.clean(depth)

    def search_pom(self, pub_key, depth, hash_commit_block, new_nonce_list, new_hash):
        poms = list()
        if pub_key in self.reinforcement_pool.keys() and depth in self.reinforcement_pool[pub_key].keys() and \
                        hash_commit_block in self.reinforcement_pool[pub_key][depth]:
            for (nonce_list, hash, signature) in self.reinforcement_pool[pub_key][depth][hash_commit_block]:
                for new_nonce in new_nonce_list:
                    for nonce in nonce_list:
                        # the same nonce is reinforcing two different propose blocks
                        if new_nonce == nonce and new_hash != hash:
                            pom_identifier = (pub_key, depth, hash_commit_block, nonce)
                            poms.append(pom_identifier)
        if poms:
            for pom_identifier in poms:
                self.miner.state.found_pom(self.get_pom(pom_identifier))

    def get_pom(self, pom_identifier):
        pub_key = pom_identifier[0]
        depth = pom_identifier[1]
        hash_commit_block = pom_identifier[2]
        nonce = pom_identifier[3]
        original_reinforcements = []
        for (nonce_list, hash, signature) in self.reinforcement_pool[pub_key][depth][hash_commit_block]:
            if nonce in nonce_list:
                message = {}
                message['nonce_list'] = nonce_list
                message['hash'] = hash
                message['depth'] = depth
                message['pub_key'] = pub_key
                original_reinforcement = (message, signature)
                original_reinforcements.append(original_reinforcement)
        return original_reinforcements

    def clean(self, depth):
        copy = self.reinforcement_pool.copy()
        for pub_key, dictionary in copy.items():
            for d in dictionary.keys():
                if d < depth:
                    self.reinforcement_pool[depth] = {}
