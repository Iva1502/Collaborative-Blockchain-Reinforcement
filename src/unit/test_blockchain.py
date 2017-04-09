from twisted.trial import unittest
from blockchain import Blockchain, CommitBlock, ProposeBlock


class TestBlockchain(unittest.TestCase):
    def test_append(self):
        self.bch = Blockchain()
        pb = ProposeBlock(0, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.bch.add_propose_block(pb, 1, self.bch.get_last()[1].hash())
        cb = CommitBlock({})
        self.bch.add_commit_block(cb, 2, self.bch.get_last()[1].next_links[0].hash())
        d, b = self.bch.get_last()
        self.assertEqual(cb, b)
        #self.assertEqual(b.weight, 1)
        self.assertEqual(d, 3)

        pb1 = ProposeBlock(36, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.bch.add_propose_block(pb1, 3, self.bch.get_last()[1].hash())
        cb1 = CommitBlock({})
        self.bch.add_commit_block(cb1, 4, self.bch.get_last()[1].next_links[0].hash())
        d, b = self.bch.get_last()
        self.assertEqual(cb1, b)
        #self.assertEqual(b.weight, 2)
        self.assertEqual(d, 5)
        self.assertEqual(len(self.bch.list_of_leaves), 1)

        pb2 = ProposeBlock(33, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.bch.add_propose_block(pb2, 3, cb.hash())
        cb2 = CommitBlock({})
        self.bch.add_commit_block(cb2, 4, pb2.hash())
        self.assertEqual(cb2, self.bch.get_last()[1])
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
        self.assertEqual(cb.hash(), cb1.hash())
        self.assertEqual(pb.hash(), pb1.hash())
