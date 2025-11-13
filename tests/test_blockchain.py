"""
Unit Tests for Blockchain Module
Tests Block and MessageBlockchain implementations
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import time
from src.core.blockchain import Block, MessageBlockchain


class TestBlock(unittest.TestCase):
    """Test cases for Block class"""
    
    def test_block_creation(self):
        """Test creating a block"""
        data = {"message": "Test"}
        block = Block(index=1, timestamp=time.time(), data=data, previous_hash="abc123")
        
        self.assertEqual(block.index, 1)
        self.assertEqual(block.data, data)
        self.assertEqual(block.previous_hash, "abc123")
    
    def test_calculate_hash(self):
        """Test hash calculation"""
        block = Block(index=1, timestamp=time.time(), data={"test": "data"}, previous_hash="0")
        hash_value = block.calculate_hash()
        
        self.assertIsInstance(hash_value, str)
        self.assertTrue(len(hash_value) > 0)
    
    def test_same_block_same_hash(self):
        """Test same block produces same hash"""
        timestamp = time.time()
        data = {"message": "Test"}
        
        block1 = Block(index=1, timestamp=timestamp, data=data, previous_hash="0")
        block2 = Block(index=1, timestamp=timestamp, data=data, previous_hash="0")
        
        self.assertEqual(block1.calculate_hash(), block2.calculate_hash())
    
    def test_mine_block(self):
        """Test block mining with proof of work"""
        block = Block(index=1, timestamp=time.time(), data={"test": "data"}, previous_hash="0")
        difficulty = 2  # Require 2 leading zeros
        
        block.mine_block(difficulty)
        
        self.assertTrue(block.hash.startswith("0" * difficulty))
        self.assertGreater(block.nonce, 0)


class TestMessageBlockchain(unittest.TestCase):
    """Test cases for MessageBlockchain class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.blockchain = MessageBlockchain(difficulty=2)
    
    def test_genesis_block_created(self):
        """Test genesis block is created"""
        self.assertEqual(len(self.blockchain.chain), 1)
        self.assertEqual(self.blockchain.chain[0].index, 0)
        self.assertEqual(self.blockchain.chain[0].previous_hash, "0")
    
    def test_add_block(self):
        """Test adding a block to the chain"""
        initial_length = len(self.blockchain.chain)
        
        data = {"sender": "Alice", "receiver": "Bob", "message": "Hello"}
        self.blockchain.add_block(data)
        
        self.assertEqual(len(self.blockchain.chain), initial_length + 1)
        self.assertEqual(self.blockchain.chain[-1].data, data)
    
    def test_chain_validity(self):
        """Test blockchain validation"""
        self.blockchain.add_block({"message": "Block 1"})
        self.blockchain.add_block({"message": "Block 2"})
        
        self.assertTrue(self.blockchain.is_chain_valid())
    
    def test_chain_linking(self):
        """Test blocks are properly linked"""
        self.blockchain.add_block({"message": "Block 1"})
        self.blockchain.add_block({"message": "Block 2"})
        
        for i in range(1, len(self.blockchain.chain)):
            current_block = self.blockchain.chain[i]
            previous_block = self.blockchain.chain[i - 1]
            
            self.assertEqual(current_block.previous_hash, previous_block.hash)
    
    def test_get_latest_block(self):
        """Test getting the latest block"""
        self.blockchain.add_block({"message": "Latest"})
        latest = self.blockchain.get_latest_block()
        
        self.assertEqual(latest.data["message"], "Latest")
        self.assertEqual(latest.index, len(self.blockchain.chain) - 1)
    
    def test_proof_of_work(self):
        """Test proof of work in added blocks"""
        self.blockchain.add_block({"message": "Test"})
        latest_block = self.blockchain.get_latest_block()
        
        self.assertTrue(latest_block.hash.startswith("0" * self.blockchain.difficulty))
    
    def test_tampered_chain_invalid(self):
        """Test tampered blockchain is detected as invalid"""
        self.blockchain.add_block({"message": "Block 1"})
        self.blockchain.add_block({"message": "Block 2"})
        
        self.blockchain.chain[1].data = {"message": "Tampered"}
        
        self.assertFalse(self.blockchain.is_chain_valid())
    
    def test_multiple_blocks(self):
        """Test adding multiple blocks"""
        for i in range(5):
            self.blockchain.add_block({"message": f"Block {i}"})
        
        self.assertEqual(len(self.blockchain.chain), 6)
        self.assertTrue(self.blockchain.is_chain_valid())
