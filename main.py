"""
Secure Messaging System (SMS)
Case Study: Integration of Security Labs 01-11

This application demonstrates:
- User Authentication (Lab 01 & 02)
- Classical Ciphers (Lab 03 & 04)
- Modern Ciphers (Lab 05)
- Hashing & Integrity (Lab 06)
- Blockchain (Lab 07)
- ElGamal & Key Distribution (Lab 09 & 11)
- Secure Data Storage (Persistent user data with encryption)
"""

import os
import sys
from src.core.authentication import UserAuthentication
from src.core.classical_ciphers import CaesarCipher, VigenereCipher
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from src.core.hashing import MessageIntegrity
from src.core.blockchain import MessageBlockchain
from src.core.elgamal import ElGamal, KeyDistributionCenter, ElGamalKeyPair
from src.core.storage import SecureStorage


class SecureMessagingSystem:
    """
    Main application integrating all security concepts
    """
    
    def __init__(self):
        # Initialize secure storage
        self.storage = SecureStorage(data_dir="data")
        
        # Initialize all components with storage
        self.auth = UserAuthentication(storage=self.storage)
        self.kdc = KeyDistributionCenter()
        self.blockchain = MessageBlockchain(difficulty=2, storage=self.storage)
        self.current_session = None
        self.current_username = None
        
        # Load existing user keys from storage
        self.user_keys = {}
        stored_keys = self.storage.load_user_keys()
        
        # Convert stored key dictionaries back to ElGamalKeyPair objects
        for username, key_data in stored_keys.items():
            if isinstance(key_data, dict):
                key_obj = ElGamalKeyPair(
                    p=key_data['p'],
                    g=key_data['g'],
                    private_key=key_data['private_key'],
                    public_key=key_data['public_key']
                )
                self.user_keys[username] = key_obj
                # Register with KDC
                self.kdc.register_user(username, key_obj)
    
    def display_banner(self):
        """Display application banner"""
        print("\n" + "="*70)
        print(" "*15 + "SECURE MESSAGING SYSTEM")
        print(" "*10 + "Information Security Labs Case Study")
        print("="*70 + "\n")
    
    def display_menu(self):
        """Display main menu"""
        if self.current_username:
            print(f"\n[Logged in as: {self.current_username}]")
            print("\n--- MAIN MENU ---")
            print("1. Send Encrypted Message")
            print("2. View My Messages")
            print("3. View Blockchain")
            print("4. Verify Blockchain Integrity")
            print("5. Storage Information")
            print("6. Logout")
            print("7. Exit")
        else:
            print("\n--- MAIN MENU ---")
            print("1. Register")
            print("2. Login")
            print("3. Storage Information")
            print("4. Exit")
    
    def register(self):
        """User registration"""
        print("\n--- USER REGISTRATION ---")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        email = input("Enter email (optional): ").strip()
        
        success, message = self.auth.register_user(username, password, email)
        print(f"\n{message}")
        
        if success:
            # Generate ElGamal keys for the user
            print("\nGenerating ElGamal key pair...")
            key_pair = ElGamal.generate_keys(bits=16)
            self.user_keys[username] = key_pair
            
            # Register public key with KDC
            self.kdc.register_user(username, key_pair)
            
            # Save keys to secure storage
            self.storage.save_user_keys(self.user_keys)
            
            print(f"✓ Public key registered with Key Distribution Center")
            print(f"✓ User data saved securely")
            print(f"  - Prime (p): {key_pair.p}")
            print(f"  - Generator (g): {key_pair.g}")
            print(f"  - Public key (y): {key_pair.public_key}")
    
    def login(self):
        """User login"""
        print("\n--- USER LOGIN ---")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        success, message = self.auth.login(username, password)
        
        if success:
            # Extract session ID from message
            self.current_session = message.split(": ")[1]
            self.current_username = username
            print(f"\n✓ {message}")
        else:
            print(f"\n✗ {message}")
    
    def logout(self):
        """User logout"""
        if self.current_session:
            self.auth.logout(self.current_session)
            print(f"\n✓ User '{self.current_username}' logged out successfully")
            self.current_session = None
            self.current_username = None
    
    def select_encryption_method(self):
        """Let user select encryption method"""
        print("\n--- SELECT ENCRYPTION METHOD ---")
        print("Classical Ciphers:")
        print("  1. Caesar Cipher")
        print("  2. Vigenère Cipher")
        print("\nModern Ciphers:")
        print("  3. XOR Stream Cipher")
        print("  4. Mini Block Cipher")
        
        choice = input("\nSelect method (1-4): ").strip()
        
        if choice == "1":
            shift = int(input("Enter shift value (default=3): ") or "3")
            return "Caesar Cipher", CaesarCipher(shift=shift)
        elif choice == "2":
            key = input("Enter Vigenère key: ").strip()
            return "Vigenère Cipher", VigenereCipher(key=key)
        elif choice == "3":
            key = input("Enter XOR key (optional, press Enter for random): ").strip()
            return "XOR Stream Cipher", XORStreamCipher(key=key if key else None)
        elif choice == "4":
            key = input("Enter block cipher key (optional, press Enter for random): ").strip()
            return "Mini Block Cipher", MiniBlockCipher(key=key if key else None)
        else:
            print("Invalid choice. Using Caesar Cipher by default.")
            return "Caesar Cipher", CaesarCipher()
    
    def send_message(self):
        """Send encrypted message"""
        print("\n--- SEND ENCRYPTED MESSAGE ---")
        
        # Check if there are other users
        registered_users = self.kdc.list_registered_users()
        available_users = [u for u in registered_users if u != self.current_username]
        
        if not available_users:
            print("No other users registered in the system.")
            return
        
        print(f"Available users: {', '.join(available_users)}")
        receiver = input("\nEnter receiver username: ").strip()
        
        # Validate receiver
        if not self.kdc.is_user_registered(receiver):
            print(f"✗ User '{receiver}' not found in KDC")
            return
        
        if receiver == self.current_username:
            print("✗ Cannot send message to yourself")
            return
        
        # Get message
        plaintext = input("\nEnter message: ").strip()
        
        if not plaintext:
            print("✗ Message cannot be empty")
            return
        
        # Step 1: Compute hash of plaintext (Lab 06)
        print("\n[Step 1] Computing SHA-256 hash of message...")
        message_hash = MessageIntegrity.compute_hash(plaintext)
        print(f"✓ Message hash: {message_hash[:32]}...")
        
        # Step 2: Select encryption method
        encryption_method, cipher = self.select_encryption_method()
        print(f"\n[Step 2] Encrypting with {encryption_method}...")
        
        # Step 3: Encrypt message
        ciphertext = cipher.encrypt(plaintext)
        print(f"✓ Message encrypted")
        print(f"  Ciphertext preview: {str(ciphertext)[:50]}...")
        
        # Step 4: Store in blockchain (Lab 07)
        print(f"\n[Step 3] Adding to blockchain...")
        block = self.blockchain.add_message_block(
            sender=self.current_username,
            receiver=receiver,
            ciphertext=str(ciphertext),
            message_hash=message_hash,
            encryption_method=encryption_method
        )
        print(f"✓ Block #{block.index} created and mined")
        print(f"  Block hash: {block.hash}")
        print(f"  Timestamp: {block.timestamp}")
        
        print(f"\n✓ Message sent successfully to {receiver}!")
    
    def view_messages(self):
        """View user's messages from blockchain"""
        print("\n--- YOUR MESSAGES ---")
        
        messages = self.blockchain.get_messages_for_user(self.current_username)
        
        if not messages:
            print("No messages found.")
            return
        
        print(f"\nFound {len(messages)} message(s):\n")
        
        for i, block in enumerate(messages, 1):
            data = block.data
            print(f"{'-'*60}")
            print(f"Message #{i} (Block #{block.index})")
            print(f"From: {data['sender']}")
            print(f"To: {data['receiver']}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Encryption: {data['encryption_method']}")
            print(f"Ciphertext: {data['ciphertext'][:50]}...")
            print(f"Hash: {data['message_hash'][:32]}...")
            print(f"Block Hash: {block.hash}")
            
            # Option to decrypt if user is receiver
            if data['receiver'] == self.current_username:
                decrypt_choice = input("\nDecrypt this message? (y/n): ").strip().lower()
                if decrypt_choice == 'y':
                    self.decrypt_message(data)
            print()
    
    def decrypt_message(self, message_data):
        """Decrypt a message"""
        encryption_method = message_data['encryption_method']
        ciphertext = message_data['ciphertext']
        original_hash = message_data['message_hash']
        
        print(f"\n[Decrypting with {encryption_method}]")
        
        try:
            # Recreate cipher based on method
            if encryption_method == "Caesar Cipher":
                shift = int(input("Enter shift value used: ") or "3")
                cipher = CaesarCipher(shift=shift)
                plaintext = cipher.decrypt(ciphertext)
            
            elif encryption_method == "Vigenère Cipher":
                key = input("Enter Vigenère key used: ").strip()
                cipher = VigenereCipher(key=key)
                plaintext = cipher.decrypt(ciphertext)
            
            elif encryption_method == "XOR Stream Cipher":
                key_hex = input("Enter XOR key (hex): ").strip()
                cipher = XORStreamCipher()
                cipher.set_key_from_hex(key_hex)
                plaintext = cipher.decrypt(ciphertext)
            
            elif encryption_method == "Mini Block Cipher":
                key_hex = input("Enter block cipher key (hex): ").strip()
                cipher = MiniBlockCipher()
                cipher.key = bytes.fromhex(key_hex)
                plaintext = cipher.decrypt(ciphertext)
            
            else:
                print("Unknown encryption method")
                return
            
            print(f"\n✓ Decrypted message: {plaintext}")
            
            # Verify hash (Lab 06)
            print("\n[Verifying message integrity...]")
            is_valid, computed_hash = MessageIntegrity.verify_hash(plaintext, original_hash)
            
            if is_valid:
                print("✓ Message integrity verified! Hash matches.")
            else:
                print("✗ WARNING: Message integrity check failed!")
                print(f"  Expected: {original_hash[:32]}...")
                print(f"  Computed: {computed_hash[:32]}...")
        
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
    
    def view_blockchain(self):
        """Display entire blockchain"""
        print("\n--- BLOCKCHAIN EXPLORER ---")
        print(f"Total blocks: {self.blockchain.get_chain_length()}")
        print(f"Mining difficulty: {self.blockchain.difficulty}\n")
        
        for block in self.blockchain.chain:
            print(f"{'='*60}")
            print(f"Block #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Previous Hash: {block.previous_hash[:32]}...")
            print(f"Block Hash: {block.hash}")
            print(f"Nonce: {block.nonce}")
            
            if block.index > 0:  # Skip genesis block details
                data = block.data
                print(f"\nMessage Data:")
                print(f"  Sender: {data['sender']}")
                print(f"  Receiver: {data['receiver']}")
                print(f"  Method: {data['encryption_method']}")
                print(f"  Hash: {data['message_hash'][:32]}...")
            print()
    
    def verify_blockchain(self):
        """Verify blockchain integrity"""
        print("\n--- BLOCKCHAIN INTEGRITY VERIFICATION ---")
        print("Verifying entire blockchain...")
        
        is_valid, message = self.blockchain.is_chain_valid()
        
        if is_valid:
            print(f"\n✓ {message}")
            print(f"  All {self.blockchain.get_chain_length()} blocks verified")
            print("  Chain integrity: INTACT")
            print("  Immutability: GUARANTEED")
        else:
            print(f"\n✗ {message}")
            print("  Chain integrity: COMPROMISED")
    
    def show_storage_info(self):
        """Display storage information"""
        print("\n--- STORAGE INFORMATION ---")
        info = self.storage.get_storage_info()
        
        print(f"\nData Directory: {info['data_directory']}")
        print(f"Encryption Enabled: {'Yes' if info['encryption_enabled'] else 'No'}")
        print(f"\nStored Files:")
        print(f"  - User Data (encrypted): {'✓' if info['users_file_exists'] else '✗'}")
        if info['users_file_exists']:
            print(f"    Size: {info.get('users_file_size', 0)} bytes")
        
        print(f"  - User Keys (encrypted): {'✓' if info['keys_file_exists'] else '✗'}")
        
        print(f"  - Blockchain (temporary): {'✓' if info['blockchain_file_exists'] else '✗'}")
        if info['blockchain_file_exists']:
            print(f"    Size: {info.get('blockchain_file_size', 0)} bytes")
            print(f"    Last Modified: {info.get('blockchain_file_modified', 'N/A')}")
        
        print(f"\nTotal Users: {len(self.auth.users)}")
        print(f"Blockchain Blocks: {self.blockchain.get_chain_length()}")
        print("\nNote: User data is encrypted using Fernet (AES-128).")
        print("Blockchain is stored temporarily and cleared on restart.")
    
    def run(self):
        """Main application loop"""
        self.display_banner()
        
        # Pre-register some test users for demo (only if no users exist)
        self.setup_demo_users()
        
        while True:
            self.display_menu()
            choice = input("\nEnter your choice: ").strip()
            
            if not self.current_username:
                # Not logged in menu
                if choice == "1":
                    self.register()
                elif choice == "2":
                    self.login()
                elif choice == "3":
                    self.show_storage_info()
                elif choice == "4":
                    print("\nExiting system. Goodbye!")
                    break
                else:
                    print("\n✗ Invalid choice")
            else:
                # Logged in menu
                if choice == "1":
                    self.send_message()
                elif choice == "2":
                    self.view_messages()
                elif choice == "3":
                    self.view_blockchain()
                elif choice == "4":
                    self.verify_blockchain()
                elif choice == "5":
                    self.show_storage_info()
                elif choice == "6":
                    self.logout()
                elif choice == "7":
                    self.logout()
                    print("\nExiting system. Goodbye!")
                    break
                else:
                    print("\n✗ Invalid choice")
    
    def setup_demo_users(self):
        """Setup demo users for testing"""
        # Only setup demo users if no users exist
        if len(self.auth.users) > 0:
            print("Found existing users in storage. Skipping demo setup.")
            return
        
        demo_users = [
            ("alice", "alice123", "alice@example.com"),
            ("bob", "bob123", "bob@example.com"),
        ]
        
        print("Setting up demo users...")
        for username, password, email in demo_users:
            success, _ = self.auth.register_user(username, password, email)
            if success:
                # Generate keys
                key_pair = ElGamal.generate_keys(bits=16)
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)
                print(f"  ✓ Demo user '{username}' registered (password: {password})")
        
        # Save all demo user keys
        if self.user_keys:
            self.storage.save_user_keys(self.user_keys)


def main():
    """Entry point"""
    try:
        app = SecureMessagingSystem()
        app.run()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted. Goodbye!")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
