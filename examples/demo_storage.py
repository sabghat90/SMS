"""
Demo script to show data directory structure
"""
import os
from src.core.storage import SecureStorage
from src.core.authentication import UserAuthentication

print("="*60)
print("Secure Storage Demo")
print("="*60)

storage = SecureStorage()
print(f"\n✓ Storage initialized")

auth = UserAuthentication(storage=storage)
auth.register_user('demo_user', 'password123', 'demo@example.com')
print(f"✓ Demo user created and saved")

print(f"\n📁 Data Directory: {os.path.abspath(storage.data_dir)}")
print("\nFiles Created:")

for filename in sorted(os.listdir(storage.data_dir)):
    filepath = os.path.join(storage.data_dir, filename)
    size = os.path.getsize(filepath)
    
    if filename == '.key':
        file_type = "Encryption Key (CRITICAL - Keep Secure!)"
        icon = "🔑"
    elif filename.endswith('.enc'):
        file_type = "Encrypted Data"
        icon = "🔒"
    elif filename.endswith('.json'):
        file_type = "Plain JSON (Temporary)"
        icon = "📄"
    else:
        file_type = "Unknown"
        icon = "📁"
    
    print(f"  {icon} {filename:<25} ({size:>6} bytes) - {file_type}")

print("\n" + "="*60)
print("Storage Information:")
print("="*60)
info = storage.get_storage_info()

print(f"\nEncryption: {'Enabled ✓' if info['encryption_enabled'] else 'Disabled ✗'}")
print(f"Users File: {'Exists ✓' if info['users_file_exists'] else 'Missing ✗'}")
print(f"Keys File: {'Exists ✓' if info['keys_file_exists'] else 'Missing ✗'}")

print("\n" + "="*60)
print("✓ Demo Complete!")
print("="*60)
print("\nNote: The data directory has been created with encrypted files.")
print("You can now run the main application and your data will persist!")
