from twisted.trial import unittest
from blockchain import Blockchain, CommitBlock, ProposeBlock
import time

class TestBlockchain(unittest.TestCase):
    def test_append(self):
        self.bch = Blockchain(int(time.time()))
        pb = ProposeBlock(0, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.bch.add_propose_block(pb, 0, self.bch.get_last()[1].hash())
        cb = CommitBlock({})
        self.bch.add_commit_block(cb, 1, self.bch.get_last()[1].next_links[0].hash(), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        d, b = self.bch.get_last()
        self.assertEqual(cb, b)
        #self.assertEqual(b.weight, 1)
        self.assertEqual(d, 1)

        pb1 = ProposeBlock(36, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.bch.add_propose_block(pb1, 1, self.bch.get_last()[1].hash())
        cb1 = CommitBlock({})
        self.bch.add_commit_block(cb1, 2, self.bch.get_last()[1].next_links[0].hash(), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        d, b = self.bch.get_last()
        self.assertEqual(cb1, b)
        #self.assertEqual(b.weight, 2)
        self.assertEqual(d, 2)
        self.assertEqual(len(self.bch.list_of_leaves), 1)

        pb2 = ProposeBlock(33, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.bch.add_propose_block(pb2, 1, cb.hash())
        cb2 = CommitBlock({})
        self.bch.add_commit_block(cb2, 2, pb2.hash(), "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDXU/1hP5P2gGCmepUxJfWa3kc+dlHob+KHZO/ZMYemJtATR1jsrdUKHd3+iC6WHG5uuCZOePYRFchEk5lirnoIiOBbQZ0aS6mVBX6lFh2zGTvfmOEpifiZvfN7iPhXDxTt9OOzKgoN1cIzbXfTM6fQfo4Ef0XYaxbiw11Fd8M4Uw==")
        self.assertEqual(cb1, self.bch.get_last()[1])
        self.assertEqual(len(self.bch.list_of_leaves), 2)

    def test_get_last(self):
        self.bch = Blockchain(int(time.time()))
        d, last = self.bch.get_last()
        self.assertEqual(last, self.bch.head.commit_link)
        self.assertEqual(0, d)

    def test_hash(self):
        pb = ProposeBlock(0)
        pb1 = ProposeBlock(0)
        cb = CommitBlock([])
        cb1 = CommitBlock([])
        self.assertEqual(cb.hash(), cb1.hash())
        self.assertEqual(pb.hash(), pb1.hash())
