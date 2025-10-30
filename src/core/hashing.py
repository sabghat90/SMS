"""
Hashing Module
Lab 06 Concept: SHA-256 hashing for integrity verification
"""

import hashlib
import hmac


class MessageIntegrity:
    """
    Handles message integrity verification using SHA-256 hashing
    """
    
    @staticmethod
    def compute_hash(message):
        """
        Compute SHA-256 hash of a message
        Returns: hexadecimal hash string
        """
        if isinstance(message, str):
            message = message.encode()
        
        hash_obj = hashlib.sha256(message)
        return hash_obj.hexdigest()
    
    @staticmethod
    def verify_hash(message, expected_hash):
        """
        Verify if message hash matches expected hash
        Returns: (is_valid: bool, computed_hash: str)
        """
        computed_hash = MessageIntegrity.compute_hash(message)
        is_valid = (computed_hash == expected_hash)
        return is_valid, computed_hash
    
    @staticmethod
    def compute_hmac(message, key):
        """
        Compute HMAC-SHA256 for message authentication
        HMAC provides both integrity and authenticity
        """
        if isinstance(message, str):
            message = message.encode()
        if isinstance(key, str):
            key = key.encode()
        
        hmac_obj = hmac.new(key, message, hashlib.sha256)
        return hmac_obj.hexdigest()
    
    @staticmethod
    def verify_hmac(message, key, expected_hmac):
        """
        Verify HMAC of a message
        Returns: (is_valid: bool, computed_hmac: str)
        """
        computed_hmac = MessageIntegrity.compute_hmac(message, key)
        is_valid = hmac.compare_digest(computed_hmac, expected_hmac)
        return is_valid, computed_hmac
    
    @staticmethod
    def hash_file(filepath):
        """
        Compute SHA-256 hash of a file
        Useful for file integrity verification
        """
        hash_obj = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError:
            return None
    
    @staticmethod
    def compute_multiple_hashes(message):
        """
        Compute multiple hash algorithms for comparison
        Returns: dictionary with different hash types
        """
        if isinstance(message, str):
            message = message.encode()
        
        hashes = {
            'md5': hashlib.md5(message).hexdigest(),
            'sha1': hashlib.sha1(message).hexdigest(),
            'sha256': hashlib.sha256(message).hexdigest(),
            'sha512': hashlib.sha512(message).hexdigest(),
        }
        
        return hashes


class MessageAuthenticationCode:
    """
    Message Authentication Code (MAC) for message authenticity
    """
    
    def __init__(self, secret_key):
        """Initialize MAC with a secret key"""
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()
        self.secret_key = secret_key
    
    def generate_mac(self, message):
        """Generate MAC for a message"""
        return MessageIntegrity.compute_hmac(message, self.secret_key)
    
    def verify_mac(self, message, mac):
        """Verify MAC for a message"""
        is_valid, _ = MessageIntegrity.verify_hmac(message, self.secret_key, mac)
        return is_valid


# Testing
if __name__ == "__main__":
    print("=== Hashing Module Tests ===\n")
    
    # Test SHA-256 Hash
    print("1. SHA-256 Hash Computation:")
    message = "Hello, World!"
    hash_value = MessageIntegrity.compute_hash(message)
    print(f"   Message: {message}")
    print(f"   SHA-256: {hash_value}\n")
    
    # Test Hash Verification
    print("2. Hash Verification:")
    is_valid, computed = MessageIntegrity.verify_hash(message, hash_value)
    print(f"   Original matches: {is_valid}")
    
    tampered_message = "Hello, World!!"
    is_valid, computed = MessageIntegrity.verify_hash(tampered_message, hash_value)
    print(f"   Tampered matches: {is_valid}")
    print(f"   Tampered hash: {computed}\n")
    
    # Test HMAC
    print("3. HMAC (Message Authentication Code):")
    key = "secret_key_123"
    hmac_value = MessageIntegrity.compute_hmac(message, key)
    print(f"   Message: {message}")
    print(f"   Key: {key}")
    print(f"   HMAC: {hmac_value}")
    
    is_valid, _ = MessageIntegrity.verify_hmac(message, key, hmac_value)
    print(f"   HMAC Valid: {is_valid}\n")
    
    # Test Multiple Hashes
    print("4. Multiple Hash Algorithms:")
    hashes = MessageIntegrity.compute_multiple_hashes(message)
    for algo, hash_val in hashes.items():
        print(f"   {algo.upper()}: {hash_val}")
    print()
    
    # Test MAC Class
    print("5. Message Authentication Code Class:")
    mac_handler = MessageAuthenticationCode("shared_secret")
    mac = mac_handler.generate_mac("Important message")
    print(f"   Generated MAC: {mac}")
    print(f"   Verification: {mac_handler.verify_mac('Important message', mac)}")
    print(f"   Tampered msg: {mac_handler.verify_mac('Tampered message', mac)}\n")
