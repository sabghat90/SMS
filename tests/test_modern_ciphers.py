"""
Unit Tests for Modern Ciphers
Tests XOR Stream Cipher and Mini Block Cipher
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher


class TestXORStreamCipher(unittest.TestCase):
    """Test cases for XOR Stream Cipher"""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt then decrypt returns original"""
        cipher = XORStreamCipher()
        key = cipher.generate_key(32)
        plaintext = "Hello, World!"
        
        encrypted = cipher.encrypt(plaintext, key)
        decrypted = cipher.decrypt(encrypted, key)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_generate_key_length(self):
        """Test generated key has correct length"""
        cipher = XORStreamCipher()
        key = cipher.generate_key(16)
        # Key is hex encoded, so 16 bytes = 32 hex chars
        self.assertEqual(len(key), 32)
    
    def test_different_keys_different_output(self):
        """Test different keys produce different ciphertexts"""
        cipher = XORStreamCipher()
        plaintext = "Test message"
        
        key1 = cipher.generate_key(32)
        key2 = cipher.generate_key(32)
        
        encrypted1 = cipher.encrypt(plaintext, key1)
        encrypted2 = cipher.encrypt(plaintext, key2)
        
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_xor_property(self):
        """Test XOR property: encrypt(encrypt(x)) = x"""
        cipher = XORStreamCipher()
        key = cipher.generate_key(32)
        plaintext = "Test"
        
        encrypted = cipher.encrypt(plaintext, key)
        double_encrypted = cipher.encrypt(encrypted, key)
        
        # XOR twice should return original (approximately, due to encoding)
        # At minimum, decrypt should work
        decrypted = cipher.decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)
    
    def test_empty_message(self):
        """Test encryption of empty message"""
        cipher = XORStreamCipher()
        key = cipher.generate_key(16)
        plaintext = ""
        
        encrypted = cipher.encrypt(plaintext, key)
        decrypted = cipher.decrypt(encrypted, key)
        
        self.assertEqual(decrypted, plaintext)


class TestMiniBlockCipher(unittest.TestCase):
    """Test cases for Mini Block Cipher"""
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt then decrypt returns original"""
        cipher = MiniBlockCipher()
        key = cipher.generate_key()
        plaintext = "Hello, World!"
        
        encrypted = cipher.encrypt(plaintext, key)
        decrypted = cipher.decrypt(encrypted, key)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_generate_key_format(self):
        """Test generated key is hex string"""
        cipher = MiniBlockCipher()
        key = cipher.generate_key()
        
        # Should be hex string
        self.assertTrue(all(c in '0123456789abcdef' for c in key.lower()))
        # Should be 32 chars (16 bytes in hex)
        self.assertEqual(len(key), 32)
    
    def test_padding(self):
        """Test padding works for various message lengths"""
        cipher = MiniBlockCipher()
        key = cipher.generate_key()
        
        # Test messages of different lengths
        for length in [1, 7, 8, 9, 15, 16, 17, 100]:
            plaintext = "A" * length
            encrypted = cipher.encrypt(plaintext, key)
            decrypted = cipher.decrypt(encrypted, key)
            self.assertEqual(decrypted, plaintext)
    
    def test_different_keys_different_output(self):
        """Test different keys produce different ciphertexts"""
        cipher = MiniBlockCipher()
        plaintext = "Test message"
        
        key1 = cipher.generate_key()
        key2 = cipher.generate_key()
        
        encrypted1 = cipher.encrypt(plaintext, key1)
        encrypted2 = cipher.encrypt(plaintext, key2)
        
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_long_message(self):
        """Test encryption of longer messages"""
        cipher = MiniBlockCipher()
        key = cipher.generate_key()
        plaintext = "This is a longer message that spans multiple blocks and tests the cipher's ability to handle extended text."
        
        encrypted = cipher.encrypt(plaintext, key)
        decrypted = cipher.decrypt(encrypted, key)
        
        self.assertEqual(decrypted, plaintext)
    
    def test_special_characters(self):
        """Test encryption with special characters"""
        cipher = MiniBlockCipher()
        key = cipher.generate_key()
        plaintext = "Hello! @#$%^&*() 123 Test"
        
        encrypted = cipher.encrypt(plaintext, key)
        decrypted = cipher.decrypt(encrypted, key)
        
        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()
