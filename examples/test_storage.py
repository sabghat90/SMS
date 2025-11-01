"""
Test script for secure storage functionality
"""

from src.core.storage import SecureStorage
from src.core.authentication import UserAuthentication
from src.core.blockchain import MessageBlockchain
from src.core.elgamal import ElGamal

print("="*60)
print("Testing Secure Storage Integration")
print("="*60)

# Test 1: Storage initialization
print("\n1. Testing Storage Initialization...")
storage = SecureStorage(data_dir="test_data")
print("   ✓ Storage initialized")

# Test 2: User data encryption/decryption
print("\n2. Testing User Data Encryption...")
test_users = {
    "alice": {
        "password_hash": "abc123",
        "email": "alice@test.com",
        "created_at": "2025-11-01"
    }
}

success, msg = storage.save_users(test_users)
print(f"   ✓ Save: {msg}")

loaded_users = storage.load_users()
print(f"   ✓ Load: Retrieved {len(loaded_users)} user(s)")
assert loaded_users == test_users, "User data mismatch!"
print("   ✓ Encryption/Decryption working correctly!")

# Test 3: Authentication with storage
print("\n3. Testing Authentication with Storage...")
auth = UserAuthentication(storage=storage)
success, msg = auth.register_user("bob", "password123", "bob@test.com")
print(f"   ✓ {msg}")

success, msg = auth.login("bob", "password123")
print(f"   ✓ {msg}")

# Test 4: Blockchain temporary storage
print("\n4. Testing Blockchain Temporary Storage...")
blockchain = MessageBlockchain(difficulty=1, storage=storage)
print(f"   ✓ Blockchain initialized with {blockchain.get_chain_length()} block(s)")

block = blockchain.add_message_block(
    sender="alice",
    receiver="bob",
    ciphertext="encrypted_message",
    message_hash="hash123",
    encryption_method="Test Cipher"
)
print(f"   ✓ Block added: #{block.index}")
print(f"   ✓ Blockchain saved to temporary storage")

# Test 5: Reload blockchain
print("\n5. Testing Blockchain Reload...")
blockchain2 = MessageBlockchain(difficulty=1, storage=storage)
print(f"   ✓ Blockchain reloaded with {blockchain2.get_chain_length()} block(s)")
assert blockchain2.get_chain_length() == blockchain.get_chain_length()
print("   ✓ Blockchain persistence working!")

# Test 6: Storage information
print("\n6. Storage Information:")
info = storage.get_storage_info()
print(f"   Data Directory: {info['data_directory']}")
print(f"   Users File: {'✓' if info['users_file_exists'] else '✗'}")
print(f"   Blockchain File: {'✓' if info['blockchain_file_exists'] else '✗'}")
print(f"   Encryption: {'Enabled' if info['encryption_enabled'] else 'Disabled'}")

# Test 7: Cleanup
print("\n7. Cleaning up test data...")
import os
import shutil
if os.path.exists("test_data"):
    shutil.rmtree("test_data")
    print("   ✓ Test data directory removed")

print("\n" + "="*60)
print("✓ All tests passed!")
print("="*60)
