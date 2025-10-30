"""
Unit Tests for Authentication Module
Tests user registration, login, and session management
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from src.core.authentication import UserAuthentication


class TestUserAuthentication(unittest.TestCase):
    """Test cases for UserAuthentication class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.auth = UserAuthentication()
    
    def test_register_new_user(self):
        """Test registering a new user"""
        result = self.auth.register("testuser", "testpass123")
        self.assertTrue(result)
        self.assertIn("testuser", self.auth.users)
    
    def test_register_duplicate_user(self):
        """Test registering duplicate username"""
        self.auth.register("testuser", "testpass123")
        result = self.auth.register("testuser", "anotherpass")
        self.assertFalse(result)
    
    def test_register_empty_username(self):
        """Test registering with empty username"""
        result = self.auth.register("", "testpass123")
        self.assertFalse(result)
    
    def test_register_empty_password(self):
        """Test registering with empty password"""
        result = self.auth.register("testuser", "")
        self.assertFalse(result)
    
    def test_login_valid_credentials(self):
        """Test login with valid credentials"""
        self.auth.register("testuser", "testpass123")
        result = self.auth.login("testuser", "testpass123")
        self.assertTrue(result)
    
    def test_login_invalid_password(self):
        """Test login with wrong password"""
        self.auth.register("testuser", "testpass123")
        result = self.auth.login("testuser", "wrongpass")
        self.assertFalse(result)
    
    def test_login_nonexistent_user(self):
        """Test login with non-existent username"""
        result = self.auth.login("nonexistent", "testpass123")
        self.assertFalse(result)
    
    def test_password_hashing(self):
        """Test that passwords are hashed, not stored plaintext"""
        self.auth.register("testuser", "testpass123")
        stored_password = self.auth.users["testuser"]["password"]
        self.assertNotEqual(stored_password, "testpass123")
        self.assertTrue(len(stored_password) > 20)  # Hash should be longer
    
    def test_session_creation(self):
        """Test session is created after login"""
        self.auth.register("testuser", "testpass123")
        self.auth.login("testuser", "testpass123")
        self.assertIn("testuser", self.auth.sessions)
    
    def test_logout(self):
        """Test logout functionality"""
        self.auth.register("testuser", "testpass123")
        self.auth.login("testuser", "testpass123")
        self.auth.logout("testuser")
        self.assertNotIn("testuser", self.auth.sessions)
    
    def test_multiple_users(self):
        """Test multiple user registrations"""
        self.auth.register("user1", "pass1")
        self.auth.register("user2", "pass2")
        self.auth.register("user3", "pass3")
        
        self.assertEqual(len(self.auth.users), 3)
        self.assertTrue(self.auth.login("user1", "pass1"))
        self.assertTrue(self.auth.login("user2", "pass2"))
        self.assertTrue(self.auth.login("user3", "pass3"))


if __name__ == "__main__":
    unittest.main()
