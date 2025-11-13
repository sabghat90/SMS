"""
Unit Tests for Hashing Module
Tests SHA-256 message integrity verification
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.core.hashing import MessageIntegrity


class TestMessageIntegrity(unittest.TestCase):
    """Test cases for MessageIntegrity class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.integrity = MessageIntegrity()
    
    def test_hash_message_returns_hash(self):
        """Test that hash_message returns a hash string"""
        message = "Test message"
        hash_value = self.integrity.hash_message(message)
        
        self.assertIsInstance(hash_value, str)
        self.assertTrue(len(hash_value) > 0)
    
    def test_same_message_same_hash(self):
        """Test that same message produces same hash"""
        message = "Test message"
        hash1 = self.integrity.hash_message(message)
        hash2 = self.integrity.hash_message(message)
        
        self.assertEqual(hash1, hash2)
    
    def test_different_messages_different_hash(self):
        """Test that different messages produce different hashes"""
        message1 = "Test message 1"
        message2 = "Test message 2"
        
        hash1 = self.integrity.hash_message(message1)
        hash2 = self.integrity.hash_message(message2)
        
        self.assertNotEqual(hash1, hash2)
    
    def test_verify_message_valid(self):
        """Test verification of valid message and hash"""
        message = "Test message"
        hash_value = self.integrity.hash_message(message)
        
        is_valid = self.integrity.verify_message(message, hash_value)
        self.assertTrue(is_valid)
    
    def test_verify_message_invalid(self):
        """Test verification fails for tampered message"""
        message = "Test message"
        hash_value = self.integrity.hash_message(message)
        
        tampered_message = "Test message!"  # Added exclamation
        is_valid = self.integrity.verify_message(tampered_message, hash_value)
        
        self.assertFalse(is_valid)
    
    def test_verify_message_wrong_hash(self):
        """Test verification fails with wrong hash"""
        message = "Test message"
        wrong_hash = "0" * 64  # Fake hash
        
        is_valid = self.integrity.verify_message(message, wrong_hash)
        self.assertFalse(is_valid)
    
    def test_hash_length(self):
        """Test SHA-256 hash is 64 hex characters"""
        message = "Test"
        hash_value = self.integrity.hash_message(message)
        
        self.assertEqual(len(hash_value), 64)
    
    def test_hash_hex_format(self):
        """Test hash is valid hexadecimal"""
        message = "Test"
        hash_value = self.integrity.hash_message(message)
        
        self.assertTrue(all(c in '0123456789abcdef' for c in hash_value.lower()))
    
    def test_empty_message(self):
        """Test hashing empty message"""
        message = ""
        hash_value = self.integrity.hash_message(message)
        
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 64)
    
    def test_long_message(self):
        """Test hashing very long message"""
        message = "A" * 10000
        hash_value = self.integrity.hash_message(message)
        
        self.assertEqual(len(hash_value), 64)
    
    def test_case_sensitivity(self):
        """Test that hash is case sensitive"""
        message1 = "Test"
        message2 = "test"
        
        hash1 = self.integrity.hash_message(message1)
        hash2 = self.integrity.hash_message(message2)
        
        self.assertNotEqual(hash1, hash2)
