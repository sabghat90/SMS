"""
Unit Tests for Classical Ciphers
Tests Caesar and Vigenère cipher implementations
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.core.classical_ciphers import CaesarCipher, VigenereCipher


class TestCaesarCipher(unittest.TestCase):
    """Test cases for Caesar Cipher"""
    
    def test_encrypt_basic(self):
        """Test basic encryption"""
        cipher = CaesarCipher(shift=3)
        plaintext = "HELLO"
        ciphertext = cipher.encrypt(plaintext)
        self.assertEqual(ciphertext, "KHOOR")
    
    def test_decrypt_basic(self):
        """Test basic decryption"""
        cipher = CaesarCipher(shift=3)
        ciphertext = "KHOOR"
        plaintext = cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, "HELLO")
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt then decrypt returns original"""
        cipher = CaesarCipher(shift=5)
        original = "HELLO WORLD"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, original)
    
    def test_different_shifts(self):
        """Test different shift values"""
        plaintext = "ABC"
        
        cipher1 = CaesarCipher(shift=1)
        self.assertEqual(cipher1.encrypt(plaintext), "BCD")
        
        cipher13 = CaesarCipher(shift=13)
        self.assertEqual(cipher13.encrypt(plaintext), "NOP")
    
    def test_wrap_around(self):
        """Test wrap around alphabet"""
        cipher = CaesarCipher(shift=3)
        self.assertEqual(cipher.encrypt("XYZ"), "ABC")
    
    def test_lowercase_conversion(self):
        """Test lowercase letters are converted to uppercase"""
        cipher = CaesarCipher(shift=3)
        encrypted = cipher.encrypt("hello")
        self.assertEqual(encrypted, "KHOOR")
    
    def test_non_alpha_characters(self):
        """Test non-alphabetic characters are preserved"""
        cipher = CaesarCipher(shift=3)
        plaintext = "HELLO, WORLD! 123"
        encrypted = cipher.encrypt(plaintext)
        # Only letters should be encrypted
        self.assertIn(",", encrypted)
        self.assertIn("!", encrypted)
        self.assertIn("1", encrypted)


class TestVigenereCipher(unittest.TestCase):
    """Test cases for Vigenère Cipher"""
    
    def test_encrypt_basic(self):
        """Test basic encryption"""
        cipher = VigenereCipher(key="KEY")
        plaintext = "HELLO"
        ciphertext = cipher.encrypt(plaintext)
        self.assertEqual(ciphertext, "RIJVS")
    
    def test_decrypt_basic(self):
        """Test basic decryption"""
        cipher = VigenereCipher(key="KEY")
        ciphertext = "RIJVS"
        plaintext = cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, "HELLO")
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt then decrypt returns original"""
        cipher = VigenereCipher(key="SECRET")
        original = "HELLO WORLD"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        self.assertEqual(decrypted, original)
    
    def test_repeating_key(self):
        """Test that key repeats for longer messages"""
        cipher = VigenereCipher(key="AB")
        # With key "AB", first char shifts by 0, second by 1, then repeat
        plaintext = "AAAA"
        encrypted = cipher.encrypt(plaintext)
        self.assertEqual(encrypted, "ABAB")
    
    def test_different_keys(self):
        """Test different keys produce different ciphertexts"""
        plaintext = "HELLO"
        
        cipher1 = VigenereCipher(key="KEY")
        cipher2 = VigenereCipher(key="DIFFERENT")
        
        encrypted1 = cipher1.encrypt(plaintext)
        encrypted2 = cipher2.encrypt(plaintext)
        
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_lowercase_key(self):
        """Test lowercase key is converted to uppercase"""
        cipher = VigenereCipher(key="key")
        plaintext = "HELLO"
        ciphertext = cipher.encrypt(plaintext)
        self.assertEqual(ciphertext, "RIJVS")
    
    def test_single_char_key(self):
        """Test single character key (should behave like Caesar)"""
        vigenere = VigenereCipher(key="C")
        caesar = CaesarCipher(shift=2)  # 'C' is shift 2
        
        plaintext = "HELLO"
        self.assertEqual(vigenere.encrypt(plaintext), caesar.encrypt(plaintext))


if __name__ == "__main__":
    unittest.main()
