"""
Secure Storage Module - Using Lab Concepts Only
Handles persistent storage of user data and temporary blockchain storage

Security Implementation:
- Lab 05: XOR Stream Cipher for encryption/decryption
- Lab 06: SHA-256 for key derivation and HMAC for integrity verification
"""

import json
import os
import hashlib
from datetime import datetime
from .modern_ciphers import XORStreamCipher
from .hashing import MessageIntegrity


class SecureStorage:
    """
    Manages secure file-based storage for application data
    Uses Lab 05 (XOR Stream Cipher) and Lab 06 (SHA-256, HMAC) concepts
    """
    
    def __init__(self, data_dir="data", master_password="SecureMessagingSystem2025"):
        """
        Initialize secure storage
        
        Args:
            data_dir: Directory to store data files
            master_password: Master password for key derivation (Lab 06 concept)
        """
        self.data_dir = data_dir
        self.users_file = os.path.join(data_dir, "users.json.enc")
        self.blockchain_file = os.path.join(data_dir, "blockchain_temp.json")
        self.keys_file = os.path.join(data_dir, "user_keys.json.enc")
        self.integrity_file = os.path.join(data_dir, ".integrity")
        
        os.makedirs(data_dir, exist_ok=True)
        
        self.encryption_key = self._derive_key(master_password)
        
        self.cipher = XORStreamCipher(key=self.encryption_key)
    
    def _derive_key(self, password):
        """
        Derive encryption key from password using SHA-256 (Lab 06 concept)
        
        Args:
            password: Master password
            
        Returns:
            16-byte encryption key
        """
        hash_value = MessageIntegrity.compute_hash(password)
        return bytes.fromhex(hash_value[:32])
    
    def _encrypt_data(self, data):
        """
        Encrypt data using XOR Stream Cipher (Lab 05 concept)
        
        Args:
            data: Dictionary to encrypt
            
        Returns:
            Tuple of (encrypted_hex, hmac_signature)
        """
        json_data = json.dumps(data, indent=2)
        
        encrypted_hex = self.cipher.encrypt(json_data)
        
        hmac_signature = MessageIntegrity.compute_hmac(
            encrypted_hex, 
            self.encryption_key.hex()
        )
        
        return encrypted_hex, hmac_signature
    
    def _decrypt_data(self, encrypted_hex, expected_hmac=None):
        """
        Decrypt data and verify integrity (Lab 05 + Lab 06 concepts)
        
        Args:
            encrypted_hex: Encrypted data in hex format
            expected_hmac: Expected HMAC signature for verification
            
        Returns:
            Decrypted dictionary or None if decryption/verification fails
        """
        try:
            if expected_hmac:
                computed_hmac = MessageIntegrity.compute_hmac(
                    encrypted_hex,
                    self.encryption_key.hex()
                )
                
                if computed_hmac != expected_hmac:
                    print("Warning: Data integrity check failed (HMAC mismatch)")
                    return None
            
            decrypted_json = self.cipher.decrypt(encrypted_hex)
            
            return json.loads(decrypted_json)
            
        except Exception as e:
            print(f"Error decrypting data: {e}")
            return None
    
    def save_users(self, users_dict):
        """
        Save user data securely (Lab 05: XOR encrypted, Lab 06: HMAC protected)
        
        Args:
            users_dict: Dictionary of user data
        """
        try:
            data_to_save = {
                'users': users_dict,
                'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'version': '2.0_lab_concepts'
            }
            
            encrypted_hex, hmac_signature = self._encrypt_data(data_to_save)
            
            combined_data = {
                'encrypted': encrypted_hex,
                'hmac': hmac_signature
            }
            
            with open(self.users_file, 'w') as f:
                json.dump(combined_data, f)
            
            self._save_integrity_hash('users', encrypted_hex)
            
            return True, "User data saved securely (XOR+HMAC)"
        except Exception as e:
            return False, f"Error saving users: {e}"
    
    def load_users(self):
        """
        Load user data from encrypted file (Lab 05 + Lab 06 verification)
        
        Returns:
            Dictionary of user data or empty dict if file doesn't exist
        """
        if not os.path.exists(self.users_file):
            return {}
        
        try:
            with open(self.users_file, 'r') as f:
                combined_data = json.load(f)
            
            encrypted_hex = combined_data.get('encrypted')
            hmac_signature = combined_data.get('hmac')
            
            if not encrypted_hex:
                return {}
            
            data = self._decrypt_data(encrypted_hex, hmac_signature)
            
            if data and 'users' in data:
                return data['users']
            return {}
        except Exception as e:
            print(f"Error loading users: {e}")
            return {}
    
    def save_user_keys(self, keys_dict):
        """
        Save ElGamal keys securely (Lab 05: XOR encrypted, Lab 06: HMAC protected)
        
        Args:
            keys_dict: Dictionary mapping username to key information
        """
        try:
            serializable_keys = {}
            for username, key_obj in keys_dict.items():
                if hasattr(key_obj, 'p'):  # ElGamal key pair object
                    serializable_keys[username] = {
                        'p': key_obj.p,
                        'g': key_obj.g,
                        'private_key': key_obj.private_key,
                        'public_key': key_obj.public_key
                    }
                else:
                    serializable_keys[username] = key_obj
            
            data_to_save = {
                'keys': serializable_keys,
                'last_updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'version': '2.0_lab_concepts'
            }
            
            encrypted_hex, hmac_signature = self._encrypt_data(data_to_save)
            
            combined_data = {
                'encrypted': encrypted_hex,
                'hmac': hmac_signature
            }
            
            with open(self.keys_file, 'w') as f:
                json.dump(combined_data, f)
            
            self._save_integrity_hash('keys', encrypted_hex)
            
            return True, "User keys saved securely (XOR+HMAC)"
        except Exception as e:
            return False, f"Error saving keys: {e}"
    
    def load_user_keys(self):
        """
        Load user keys from encrypted file (Lab 05 + Lab 06 verification)
        
        Returns:
            Dictionary of user keys or empty dict if file doesn't exist
        """
        if not os.path.exists(self.keys_file):
            return {}
        
        try:
            with open(self.keys_file, 'r') as f:
                combined_data = json.load(f)
            
            encrypted_hex = combined_data.get('encrypted')
            hmac_signature = combined_data.get('hmac')
            
            if not encrypted_hex:
                return {}
            
            data = self._decrypt_data(encrypted_hex, hmac_signature)
            
            if data and 'keys' in data:
                return data['keys']
            return {}
        except Exception as e:
            print(f"Error loading keys: {e}")
            return {}
    
    def _save_integrity_hash(self, file_type, data):
        """
        Save SHA-256 hash of data for integrity verification (Lab 06 concept)
        
        Args:
            file_type: Type of file ('users' or 'keys')
            data: Data to hash
        """
        try:
            data_hash = MessageIntegrity.compute_hash(data)
            
            integrity_data = {}
            if os.path.exists(self.integrity_file):
                with open(self.integrity_file, 'r') as f:
                    integrity_data = json.load(f)
            
            integrity_data[file_type] = {
                'hash': data_hash,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.integrity_file, 'w') as f:
                json.dump(integrity_data, f, indent=2)
                
        except Exception as e:
            print(f"Warning: Could not save integrity hash: {e}")
    
    def verify_file_integrity(self, file_type):
        """
        Verify file integrity using stored SHA-256 hash (Lab 06 concept)
        
        Args:
            file_type: Type of file to verify ('users' or 'keys')
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            if not os.path.exists(self.integrity_file):
                return False, "No integrity data found"
            
            with open(self.integrity_file, 'r') as f:
                integrity_data = json.load(f)
            
            if file_type not in integrity_data:
                return False, f"No integrity hash for {file_type}"
            
            expected_hash = integrity_data[file_type]['hash']
            
            file_path = self.users_file if file_type == 'users' else self.keys_file
            if not os.path.exists(file_path):
                return False, f"{file_type} file not found"
            
            with open(file_path, 'r') as f:
                current_data = json.load(f)
            
            current_encrypted = current_data.get('encrypted', '')
            
            current_hash = MessageIntegrity.compute_hash(current_encrypted)
            
            if current_hash == expected_hash:
                return True, f"{file_type} integrity verified"
            else:
                return False, f"{file_type} integrity check failed - file may be corrupted"
                
        except Exception as e:
            return False, f"Error verifying integrity: {e}"
    
    def save_blockchain_temp(self, blockchain_data):
        """
        Save blockchain temporarily (unencrypted for debugging/demo)
        This is temporary storage and will be cleared on restart
        
        Args:
            blockchain_data: List of block dictionaries
        """
        try:
            blockchain_json = json.dumps(blockchain_data, sort_keys=True)
            blockchain_hash = MessageIntegrity.compute_hash(blockchain_json)
            
            data_to_save = {
                'blockchain': blockchain_data,
                'hash': blockchain_hash,
                'saved_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'note': 'Temporary blockchain storage - cleared on restart'
            }
            
            with open(self.blockchain_file, 'w') as f:
                json.dump(data_to_save, f, indent=2)
            
            return True, "Blockchain saved temporarily with integrity hash"
        except Exception as e:
            return False, f"Error saving blockchain: {e}"
    
    def load_blockchain_temp(self):
        """
        Load temporary blockchain data with integrity verification (Lab 06)
        
        Returns:
            List of block data or None if file doesn't exist or verification fails
        """
        if not os.path.exists(self.blockchain_file):
            return None
        
        try:
            with open(self.blockchain_file, 'r') as f:
                data = json.load(f)
            
            if not data or 'blockchain' not in data:
                return None
            
            if 'hash' in data:
                blockchain_json = json.dumps(data['blockchain'], sort_keys=True)
                computed_hash = MessageIntegrity.compute_hash(blockchain_json)
                
                if computed_hash != data['hash']:
                    print("Warning: Blockchain integrity check failed")
                    return None
            
            return data['blockchain']
            
        except Exception as e:
            print(f"Error loading blockchain: {e}")
            return None
    
    def clear_blockchain_temp(self):
        """Clear temporary blockchain storage"""
        try:
            if os.path.exists(self.blockchain_file):
                os.remove(self.blockchain_file)
            return True, "Temporary blockchain cleared"
        except Exception as e:
            return False, f"Error clearing blockchain: {e}"
    
    def get_storage_info(self):
        """Get information about stored data with security details"""
        info = {
            'data_directory': os.path.abspath(self.data_dir),
            'users_file_exists': os.path.exists(self.users_file),
            'keys_file_exists': os.path.exists(self.keys_file),
            'blockchain_file_exists': os.path.exists(self.blockchain_file),
            'encryption_method': 'XOR Stream Cipher (Lab 05)',
            'integrity_method': 'HMAC-SHA256 (Lab 06)',
            'key_derivation': 'SHA-256 (Lab 06)'
        }
        
        if os.path.exists(self.users_file):
            info['users_file_size'] = os.path.getsize(self.users_file)
            valid, msg = self.verify_file_integrity('users')
            info['users_integrity'] = msg
        
        if os.path.exists(self.keys_file):
            info['keys_file_size'] = os.path.getsize(self.keys_file)
            valid, msg = self.verify_file_integrity('keys')
            info['keys_integrity'] = msg
        
        if os.path.exists(self.blockchain_file):
            info['blockchain_file_size'] = os.path.getsize(self.blockchain_file)
            info['blockchain_file_modified'] = datetime.fromtimestamp(
                os.path.getmtime(self.blockchain_file)
            ).strftime("%Y-%m-%d %H:%M:%S")
        
        return info
    
    def backup_data(self, backup_dir="backups"):
        """
        Create a backup of all data files with integrity verification
        """
        try:
            backup_path = os.path.join(self.data_dir, backup_dir)
            os.makedirs(backup_path, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_manifest = {
                'timestamp': timestamp,
                'files': {},
                'method': 'Lab concepts (XOR + HMAC)'
            }
            
            if os.path.exists(self.users_file):
                backup_file = os.path.join(backup_path, f"users_{timestamp}.json.enc")
                with open(self.users_file, 'r') as src:
                    data = src.read()
                    with open(backup_file, 'w') as dst:
                        dst.write(data)
                    backup_manifest['files']['users'] = MessageIntegrity.compute_hash(data)
            
            if os.path.exists(self.keys_file):
                backup_file = os.path.join(backup_path, f"keys_{timestamp}.json.enc")
                with open(self.keys_file, 'r') as src:
                    data = src.read()
                    with open(backup_file, 'w') as dst:
                        dst.write(data)
                    backup_manifest['files']['keys'] = MessageIntegrity.compute_hash(data)
            
            manifest_file = os.path.join(backup_path, f"manifest_{timestamp}.json")
            with open(manifest_file, 'w') as f:
                json.dump(backup_manifest, f, indent=2)
            
            return True, f"Backup created at {backup_path} with integrity hashes"
        except Exception as e:
            return False, f"Backup failed: {e}"
