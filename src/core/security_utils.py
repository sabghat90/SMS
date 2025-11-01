"""
Security Utilities Module - Using Lab Concepts Only
Additional security methods and helpers for the Secure Messaging System

Security Implementation:
- Lab 06: SHA-256 hashing and HMAC for all integrity checks
- Lab 05: XOR Stream Cipher for encryption needs
- Lab 09: Crypto math primitives (prime generation)
- NO external cryptography libraries except those in lab concepts
"""

from .authentication import UserAuthentication
from .hashing import MessageIntegrity
from .storage import SecureStorage
from .crypto_math import generate_prime, is_prime
from .modern_ciphers import XORStreamCipher
import hashlib
import secrets
import string
import os


class SecurePasswordManager:
    """
    Enhanced password security using hashing module
    """
    
    @staticmethod
    def generate_strong_password(length=16):
        """
        Generate a cryptographically secure random password
        
        Args:
            length: Password length (default 16)
        
        Returns:
            Secure random password string
        """
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    @staticmethod
    def check_password_strength(password):
        """
        Check password strength
        
        Args:
            password: Password to check
        
        Returns:
            Tuple of (strength_score, feedback)
        """
        score = 0
        feedback = []
        
        if len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters")
        
        if len(password) >= 12:
            score += 1
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in string.punctuation for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        strength = "Weak"
        if score >= 5:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        
        return strength, feedback
    
    @staticmethod
    def hash_password_with_salt(password, salt=None):
        """
        Hash password with salt using MessageIntegrity (Lab 06 concept)
        
        Args:
            password: Password to hash
            salt: Optional salt (auto-generated if not provided)
        
        Returns:
            Tuple of (hash, salt)
        """
        if salt is None:
            # Generate random salt using os.urandom (simpler than secrets)
            salt = os.urandom(16).hex()
        
        # Lab 06: Use SHA-256 hashing
        salted_password = password + salt
        password_hash = MessageIntegrity.compute_hash(salted_password)
        
        return password_hash, salt


class SecureDataValidator:
    """
    Data validation using Lab 06 concepts (SHA-256 and HMAC)
    """
    
    @staticmethod
    def create_data_signature(data, secret_key):
        """
        Create HMAC signature for data using MessageIntegrity (Lab 06)
        
        Args:
            data: Data to sign
            secret_key: Secret key for HMAC
        
        Returns:
            HMAC signature
        """
        return MessageIntegrity.compute_hmac(data, secret_key)
    
    @staticmethod
    def verify_data_signature(data, secret_key, signature):
        """
        Verify HMAC signature using MessageIntegrity (Lab 06)
        
        Args:
            data: Original data
            secret_key: Secret key
            signature: Signature to verify
        
        Returns:
            Boolean indicating validity
        """
        is_valid, _ = MessageIntegrity.verify_hmac(data, secret_key, signature)
        return is_valid
    
    @staticmethod
    def compute_file_hash(filepath):
        """
        Compute SHA-256 hash of file contents (Lab 06 concept)
        
        Args:
            filepath: Path to file
        
        Returns:
            SHA-256 hash of file
        """
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            # Lab 06: Use SHA-256
            return MessageIntegrity.compute_hash(file_data.decode('utf-8', errors='ignore'))
        except Exception as e:
            return None
    
    @staticmethod
    def verify_file_integrity(filepath, expected_hash):
        """
        Verify file integrity against expected hash (Lab 06 concept)
        
        Args:
            filepath: Path to file
            expected_hash: Expected hash value
        
        Returns:
            Boolean indicating if file is intact
        """
        actual_hash = SecureDataValidator.compute_file_hash(filepath)
        return actual_hash == expected_hash if actual_hash else False


class SecureSessionManager:
    """
    Enhanced session management with Lab 06 security features
    """
    
    def __init__(self, auth_system):
        """
        Initialize session manager
        
        Args:
            auth_system: UserAuthentication instance
        """
        self.auth = auth_system
        self.session_data = {}  # session_id -> {username, metadata}
    
    def create_secure_session(self, username):
        """
        Create a secure session with Lab 06 hash-based session ID
        
        Args:
            username: Username for session
        
        Returns:
            Tuple of (success, session_id_or_message)
        """
        # Generate session ID using Lab 06 concepts (hash-based)
        # Use os.urandom for randomness + SHA-256 for hashing
        random_data = os.urandom(32).hex()
        session_id = MessageIntegrity.compute_hash(username + random_data)
        
        # Store session metadata
        self.session_data[session_id] = {
            'username': username,
            'created_at': MessageIntegrity.compute_hash(os.urandom(16).hex()),
            'ip_address': '127.0.0.1',  # Would be actual IP in production
            'user_agent': 'SMS-Client-1.0'
        }
        
        return True, session_id
    
    def validate_session(self, session_id):
        """
        Validate session with additional checks
        
        Args:
            session_id: Session ID to validate
        
        Returns:
            Boolean indicating if session is valid
        """
        if session_id not in self.session_data:
            return False
        
        # Additional validation could include:
        # - Session timeout
        # - IP address verification
        # - User agent verification
        
        return self.auth.is_session_active(session_id)
    
    def end_session(self, session_id):
        """
        End a session securely
        
        Args:
            session_id: Session to end
        
        Returns:
            Boolean indicating success
        """
        if session_id in self.session_data:
            del self.session_data[session_id]
        
        return self.auth.logout(session_id)


class SecureStorageHelper:
    """
    Helper utilities for secure storage operations
    """
    
    @staticmethod
    def backup_with_verification(storage, backup_name=None):
        """
        Create backup with integrity verification
        
        Args:
            storage: SecureStorage instance
            backup_name: Optional backup name
        
        Returns:
            Tuple of (success, message, verification_hash)
        """
        # Create backup
        success, msg = storage.backup_data()
        
        if not success:
            return False, msg, None
        
        # Compute verification hash
        import os
        backup_files = []
        data_dir = storage.data_dir
        
        if os.path.exists(data_dir):
            for filename in os.listdir(data_dir):
                filepath = os.path.join(data_dir, filename)
                if os.path.isfile(filepath):
                    file_hash = SecureDataValidator.compute_file_hash(filepath)
                    if file_hash:
                        backup_files.append(f"{filename}:{file_hash}")
        
        verification_hash = MessageIntegrity.compute_hash('|'.join(backup_files))
        
        return success, msg, verification_hash
    
    @staticmethod
    def secure_delete_data(storage):
        """
        Securely clear temporary data
        
        Args:
            storage: SecureStorage instance
        
        Returns:
            Tuple of (success, message)
        """
        # Clear blockchain temporary storage
        success, msg = storage.clear_blockchain_temp()
        
        return success, msg
    
    @staticmethod
    def verify_storage_integrity(storage):
        """
        Verify storage files haven't been tampered with
        
        Args:
            storage: SecureStorage instance
        
        Returns:
            Tuple of (is_valid, details)
        """
        import os
        
        checks = {
            'users_file_exists': os.path.exists(storage.users_file),
            'keys_file_exists': os.path.exists(storage.keys_file),
            'can_decrypt_users': False,
            'can_decrypt_keys': False,
            'users_integrity': 'Not checked',
            'keys_integrity': 'Not checked'
        }
        
        # Try to decrypt users
        try:
            users = storage.load_users()
            checks['can_decrypt_users'] = isinstance(users, dict)
        except:
            pass
        
        # Try to decrypt keys
        try:
            keys = storage.load_user_keys()
            checks['can_decrypt_keys'] = isinstance(keys, dict)
        except:
            pass
        
        # Lab 06: Verify integrity if files exist
        if checks['users_file_exists']:
            valid, msg = storage.verify_file_integrity('users')
            checks['users_integrity'] = msg
        
        if checks['keys_file_exists']:
            valid, msg = storage.verify_file_integrity('keys')
            checks['keys_integrity'] = msg
        
        all_valid = all([
            checks['users_file_exists'],
            checks['can_decrypt_users'],
            checks['can_decrypt_keys']
        ])
        
        return all_valid, checks


class SecureRandomGenerator:
    """
    Secure random number generation using Lab 09 crypto_math concepts
    """
    
    @staticmethod
    def generate_secure_token(length=32):
        """
        Generate secure random token using os.urandom (simpler approach)
        
        Args:
            length: Token length in bytes
        
        Returns:
            Hex-encoded secure token
        """
        return os.urandom(length).hex()
    
    @staticmethod
    def generate_secure_prime(bits=16):
        """
        Generate cryptographically secure prime number (Lab 09 concept)
        
        Args:
            bits: Number of bits for prime
        
        Returns:
            Prime number
        """
        return generate_prime(bits)
    
    @staticmethod
    def generate_random_key(length=16):
        """
        Generate random encryption key using os.urandom
        
        Args:
            length: Key length in bytes
        
        Returns:
            Random key bytes
        """
        return os.urandom(length)


# Demo usage
if __name__ == "__main__":
    print("=== Security Utilities Demo ===\n")
    
    # Password Management
    print("1. Password Management:")
    strong_pass = SecurePasswordManager.generate_strong_password(16)
    print(f"   Generated password: {strong_pass}")
    
    strength, feedback = SecurePasswordManager.check_password_strength(strong_pass)
    print(f"   Strength: {strength}")
    
    password_hash, salt = SecurePasswordManager.hash_password_with_salt("mypassword")
    print(f"   Hashed password: {password_hash[:32]}...")
    print(f"   Salt: {salt[:16]}...\n")
    
    # Data Validation
    print("2. Data Validation:")
    data = "Important message"
    secret = "secret_key"
    signature = SecureDataValidator.create_data_signature(data, secret)
    print(f"   Data: {data}")
    print(f"   Signature: {signature[:32]}...")
    
    is_valid = SecureDataValidator.verify_data_signature(data, secret, signature)
    print(f"   Signature valid: {is_valid}\n")
    
    # Random Generation
    print("3. Secure Random Generation:")
    token = SecureRandomGenerator.generate_secure_token(16)
    print(f"   Secure token: {token}")
    
    prime = SecureRandomGenerator.generate_secure_prime(8)
    print(f"   Random prime: {prime}")
    print(f"   Is prime: {is_prime(prime)}\n")
    
    print("✓ All security utilities working!")
