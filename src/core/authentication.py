"""
User Authentication Module
Lab 01 & Lab 02 Concepts: Python basics, collections (dictionaries), conditionals
Handles user registration and login using secure credential storage
"""

import hashlib
from datetime import datetime


class UserAuthentication:
    """Manages user registration and authentication"""
    
    def __init__(self):
        # Dictionary to store user credentials
        # Format: {username: {'password_hash': hash, 'created_at': timestamp, 'email': email}}
        self.users = {}
        # Dictionary to store active sessions
        self.active_sessions = {}
    
    def _hash_password(self, password):
        """Hash password using SHA-256 for secure storage"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username, password, email=""):
        """
        Register a new user
        Returns: (success: bool, message: str)
        """
        # Validation checks (conditionals)
        if not username or not password:
            return False, "Username and password cannot be empty"
        
        if username in self.users:
            return False, "Username already exists"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        
        # Store user credentials in dictionary
        self.users[username] = {
            'password_hash': self._hash_password(password),
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'email': email,
            'login_count': 0
        }
        
        return True, f"User '{username}' registered successfully!"
    
    def login(self, username, password):
        """
        Authenticate user login
        Returns: (success: bool, message: str)
        """
        # Check if user exists (conditional)
        if username not in self.users:
            return False, "Invalid username or password"
        
        # Verify password
        password_hash = self._hash_password(password)
        if self.users[username]['password_hash'] != password_hash:
            return False, "Invalid username or password"
        
        # Create active session
        session_id = hashlib.sha256(f"{username}{datetime.now()}".encode()).hexdigest()[:16]
        self.active_sessions[session_id] = {
            'username': username,
            'login_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Update login count
        self.users[username]['login_count'] += 1
        
        return True, f"Login successful! Session ID: {session_id}"
    
    def logout(self, session_id):
        """Logout user and end session"""
        if session_id in self.active_sessions:
            username = self.active_sessions[session_id]['username']
            del self.active_sessions[session_id]
            return True, f"User '{username}' logged out successfully"
        return False, "Invalid session"
    
    def get_user_info(self, username):
        """Get user information (excluding password hash)"""
        if username not in self.users:
            return None
        
        user_info = self.users[username].copy()
        user_info.pop('password_hash', None)
        return user_info
    
    def is_session_active(self, session_id):
        """Check if a session is active"""
        return session_id in self.active_sessions
    
    def get_username_from_session(self, session_id):
        """Get username from session ID"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]['username']
        return None
    
    def list_users(self):
        """List all registered users (for admin purposes)"""
        return list(self.users.keys())
    
    def change_password(self, username, old_password, new_password):
        """Change user password"""
        if username not in self.users:
            return False, "User not found"
        
        # Verify old password
        old_hash = self._hash_password(old_password)
        if self.users[username]['password_hash'] != old_hash:
            return False, "Incorrect old password"
        
        if len(new_password) < 6:
            return False, "New password must be at least 6 characters long"
        
        # Update password
        self.users[username]['password_hash'] = self._hash_password(new_password)
        return True, "Password changed successfully"


# Testing
if __name__ == "__main__":
    print("=== User Authentication Module Tests ===\n")
    
    auth = UserAuthentication()
    
    # Test Registration
    print("1. User Registration:")
    success, msg = auth.register_user("alice", "alice123", "alice@example.com")
    print(f"   Register Alice: {msg}")
    
    success, msg = auth.register_user("bob", "bob123", "bob@example.com")
    print(f"   Register Bob: {msg}")
    
    success, msg = auth.register_user("alice", "password")
    print(f"   Duplicate Alice: {msg}\n")
    
    # Test Login
    print("2. User Login:")
    success, msg = auth.login("alice", "alice123")
    print(f"   Alice login: {msg}")
    if success:
        alice_session = msg.split(": ")[1]
    
    success, msg = auth.login("bob", "wrongpass")
    print(f"   Bob wrong password: {msg}\n")
    
    # Test User Info
    print("3. User Information:")
    info = auth.get_user_info("alice")
    print(f"   Alice info: {info}\n")
    
    # Test List Users
    print("4. List All Users:")
    print(f"   Registered users: {auth.list_users()}\n")
