class Blockchain:
    def __init__(self):
        self.head = ProposeBlock(0, None)
        self.head.commit_link = CommitBlock([], self.head)

    def getLast(self):
        queue = list(self.head.commit_link.next_links)
        while queue:
            node = queue.pop()
            queue.extend(node.commit_link.next_links)

    def addProposeBlock(self, block, depth, hash):
        node = self.bfs(depth, hash, "commit")
        if node != None:
            node.next_links.append(block)
            block.prev_link = node

    def addCommitBlock(self, block, depth, hash):
        node = self.bfs(depth, hash, "propose")
        if node != None:
            node.commit_link = block
            block.propose_link = node

    def bfs(self, depth, hash, type):
        queue = list(self.head.commit_link.next_links)
        while queue:
            node = queue.pop(0)
            queue.extend(node.commit_link.next_links)

class ProposeBlock:
    def __init__(self, nonce, prev_link):
        self.nonce = nonce
        self.prev_link = None
        self.commit_link = None

class CommitBlock:
    def __init__(self, reinf_list, propose_link):
        self.reinforcements = reinf_list
        self.propose_link = propose_link
        self.next_links = []