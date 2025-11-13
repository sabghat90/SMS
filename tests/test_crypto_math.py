"""
Unit Tests for Cryptographic Math Module
Tests mathematical primitives for cryptography
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.core.crypto_math import gcd, extended_gcd, mod_inverse, is_prime, power_mod


class TestCryptoMath(unittest.TestCase):
    """Test cases for cryptographic math functions"""
    
    def test_gcd_basic(self):
        """Test GCD with basic inputs"""
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(100, 50), 50)
        self.assertEqual(gcd(17, 13), 1)
    
    def test_gcd_coprime(self):
        """Test GCD with coprime numbers"""
        self.assertEqual(gcd(25, 36), 1)
        self.assertEqual(gcd(7, 11), 1)
    
    def test_gcd_same_number(self):
        """Test GCD of number with itself"""
        self.assertEqual(gcd(42, 42), 42)
    
    def test_gcd_zero(self):
        """Test GCD with zero"""
        self.assertEqual(gcd(0, 5), 5)
        self.assertEqual(gcd(5, 0), 5)
    
    def test_extended_gcd(self):
        """Test extended GCD algorithm"""
        g, x, y = extended_gcd(48, 18)
        
        self.assertEqual(g, 6)
        
        self.assertEqual(48 * x + 18 * y, g)
    
    def test_extended_gcd_coprime(self):
        """Test extended GCD with coprime numbers"""
        g, x, y = extended_gcd(17, 13)
        
        self.assertEqual(g, 1)
        self.assertEqual(17 * x + 13 * y, 1)
    
    def test_mod_inverse_exists(self):
        """Test modular inverse when it exists"""
        inv = mod_inverse(3, 7)
        self.assertEqual((3 * inv) % 7, 1)
    
    def test_mod_inverse_coprime(self):
        """Test modular inverse with various coprime pairs"""
        test_cases = [(7, 26), (15, 26), (5, 11)]
        
        for a, m in test_cases:
            inv = mod_inverse(a, m)
            if inv is not None:
                self.assertEqual((a * inv) % m, 1)
    
    def test_mod_inverse_not_exists(self):
        """Test modular inverse when it doesn't exist"""
        with self.assertRaises(ValueError):
            mod_inverse(6, 9)
    
    def test_is_prime_known_primes(self):
        """Test is_prime with known prime numbers"""
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        
        for p in primes:
            self.assertTrue(is_prime(p), f"{p} should be prime")
    
    def test_is_prime_known_composites(self):
        """Test is_prime with known composite numbers"""
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20]
        
        for n in composites:
            self.assertFalse(is_prime(n), f"{n} should not be prime")
    
    def test_is_prime_edge_cases(self):
        """Test is_prime with edge cases"""
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(1))
        self.assertTrue(is_prime(2))
    
    def test_is_prime_large_primes(self):
        """Test is_prime with larger prime numbers"""
        large_primes = [97, 101, 103, 107, 109]
        
        for p in large_primes:
            self.assertTrue(is_prime(p))
    
    def test_power_mod_basic(self):
        """Test modular exponentiation"""
        result = power_mod(2, 10, 1000)
        self.assertEqual(result, 24)
    
    def test_power_mod_large(self):
        """Test modular exponentiation with large numbers"""
        result = power_mod(3, 100, 7)
        
        self.assertIsInstance(result, int)
        self.assertLess(result, 7)
    
    def test_power_mod_zero_exponent(self):
        """Test modular exponentiation with zero exponent"""
        result = power_mod(5, 0, 7)
        self.assertEqual(result, 1)
    
    def test_power_mod_one_exponent(self):
        """Test modular exponentiation with exponent 1"""
        result = power_mod(5, 1, 7)
        self.assertEqual(result, 5)
    
    def test_fermat_little_theorem(self):
        """Test Fermat's Little Theorem using power_mod"""
        p = 7
        a = 3
        
        result = power_mod(a, p - 1, p)
        self.assertEqual(result, 1)
