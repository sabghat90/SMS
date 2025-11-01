"""
Test server initialization and data directory creation
"""
import os
import shutil

# Clean up first
if os.path.exists("data"):
    shutil.rmtree("data")
    print("✓ Cleaned up existing data directory")

# Initialize server
from src.network.server import MessageServer

print("\nInitializing server...")
server = MessageServer()

# Check data directory
print("\n" + "="*60)
print("Data Directory Status:")
print("="*60)

if os.path.exists("data"):
    print("✓ Data directory created!")
    print(f"\nFiles in data directory:")
    for filename in sorted(os.listdir("data")):
        filepath = os.path.join("data", filename)
        size = os.path.getsize(filepath)
        print(f"  - {filename:<25} ({size:>6} bytes)")
    
    print(f"\n✓ Total users: {len(server.auth.users)}")
    print(f"✓ User names: {list(server.auth.users.keys())}")
    print(f"✓ Blockchain blocks: {server.blockchain.get_chain_length()}")
else:
    print("✗ Data directory NOT created!")

print("\n" + "="*60)
print("✓ Server test complete!")
print("="*60)
