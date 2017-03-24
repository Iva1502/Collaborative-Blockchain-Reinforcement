from twisted.trial import unittest
from blockchain import Blockchain, CommitBlock, ProposeBlock

class TestBlockchain(unittest.TestCase):
    def test_append(self):
        self.bch = Blockchain()
        pb = ProposeBlock(0)
        self.bch.add_propose_block(pb, 1, hash(self.bch.get_last()[1]))
        cb = CommitBlock([])
        self.bch.add_commit_block(cb, 2, hash(self.bch.get_last()[1].next_links[0]))
        d, b = self.bch.get_last()
        self.assertEqual(cb, b)
        self.assertEqual(b.weight, 1)
        self.assertEqual(d, 3)

        pb1 = ProposeBlock(36)
        self.bch.add_propose_block(pb1, 3, hash(self.bch.get_last()[1]))
        cb1 = CommitBlock([])
        self.bch.add_commit_block(cb1, 4, hash(self.bch.get_last()[1].next_links[0]))
        d, b = self.bch.get_last()
        self.assertEqual(cb1, b)
        self.assertEqual(b.weight, 2)
        self.assertEqual(d, 5)
        self.assertEqual(len(self.bch.list_of_leaves), 1)

        pb2 = ProposeBlock(33)
        self.bch.add_propose_block(pb2, 3, hash(cb))
        cb2 = CommitBlock([])
        self.bch.add_commit_block(cb2, 4, hash(pb2))
        self.assertEqual(cb1, self.bch.get_last()[1])
        self.assertEqual(len(self.bch.list_of_leaves), 2)

    def test_get_last(self):
        self.bch = Blockchain()
        d, last = self.bch.get_last()
        self.assertEqual(last, self.bch.head.commit_link)
        self.assertEqual(1, d)

    def test_hash(self):
        pb = ProposeBlock(0)
        pb1 = ProposeBlock(0)
        cb = CommitBlock([])
        cb1 = CommitBlock([])
        self.assertEqual(hash(cb), hash(cb1))
        self.assertEqual(hash(pb), hash(pb1))
