"""
Blockchain Module
Lab 07 Concept: Blockchain for message logging with immutability and non-repudiation
Each encrypted message is stored as a block in the blockchain
"""

import hashlib
import json
from datetime import datetime


class Block:
    """
    Represents a single block in the blockchain
    Contains message transaction data
    """
    
    def __init__(self, index, timestamp, data, previous_hash):
        """
        Initialize a block
        
        Args:
            index: Position of block in chain
            timestamp: When the block was created
            data: Dictionary containing message data
            previous_hash: Hash of the previous block
        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        """
        Calculate SHA-256 hash of the block
        Ensures immutability
        """
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty=2):
        """
        Proof of Work: Mine block with specified difficulty
        Difficulty determines number of leading zeros required
        """
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        return self.hash
    
    def to_dict(self):
        """Convert block to dictionary for serialization"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "nonce": self.nonce
        }


class MessageBlockchain:
    """
    Blockchain for storing encrypted messages
    Provides immutability and non-repudiation
    """
    
    def __init__(self, difficulty=2):
        """
        Initialize blockchain with genesis block
        
        Args:
            difficulty: Mining difficulty (number of leading zeros)
        """
        self.chain = []
        self.difficulty = difficulty
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_block = Block(
            index=0,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data={
                "sender": "System",
                "receiver": "System",
                "message": "Genesis Block",
                "hash": "0" * 64
            },
            previous_hash="0"
        )
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
    
    def get_latest_block(self):
        """Return the most recent block in the chain"""
        return self.chain[-1]
    
    def add_message_block(self, sender, receiver, ciphertext, message_hash, encryption_method):
        """
        Add a new message block to the blockchain
        
        Args:
            sender: Username of sender
            receiver: Username of receiver
            ciphertext: Encrypted message
            message_hash: SHA-256 hash of original plaintext
            encryption_method: Cipher used for encryption
        
        Returns:
            The newly created block
        """
        previous_block = self.get_latest_block()
        
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data={
                "sender": sender,
                "receiver": receiver,
                "ciphertext": ciphertext,
                "message_hash": message_hash,
                "encryption_method": encryption_method
            },
            previous_hash=previous_block.hash
        )
        
        # Mine the block
        new_block.mine_block(self.difficulty)
        
        # Add to chain
        self.chain.append(new_block)
        
        return new_block
    
    def is_chain_valid(self):
        """
        Verify the integrity of the entire blockchain
        Checks:
        1. Each block's hash is valid
        2. Each block correctly references previous block
        
        Returns:
            (is_valid: bool, message: str)
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify current block's hash
            if current_block.hash != current_block.calculate_hash():
                return False, f"Block {i} has invalid hash"
            
            # Verify link to previous block
            if current_block.previous_hash != previous_block.hash:
                return False, f"Block {i} has invalid previous hash"
        
        return True, "Blockchain is valid"
    
    def get_messages_for_user(self, username):
        """
        Retrieve all messages sent to or from a specific user
        
        Args:
            username: Username to filter messages
        
        Returns:
            List of blocks containing messages for the user
        """
        user_messages = []
        
        for block in self.chain[1:]:  # Skip genesis block
            if (block.data.get("sender") == username or 
                block.data.get("receiver") == username):
                user_messages.append(block)
        
        return user_messages
    
    def get_block_by_index(self, index):
        """Retrieve a specific block by index"""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def display_chain(self):
        """Display the entire blockchain"""
        for block in self.chain:
            print(f"\n{'='*60}")
            print(f"Block #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Data: {json.dumps(block.data, indent=2)}")
            print(f"Previous Hash: {block.previous_hash}")
            print(f"Hash: {block.hash}")
            print(f"Nonce: {block.nonce}")
    
    def get_chain_length(self):
        """Return the number of blocks in the chain"""
        return len(self.chain)
    
    def export_chain(self):
        """Export blockchain to JSON format"""
        return json.dumps([block.to_dict() for block in self.chain], indent=2)


# Testing
if __name__ == "__main__":
    print("=== Blockchain Module Tests ===\n")
    
    # Create blockchain
    print("1. Creating Blockchain:")
    blockchain = MessageBlockchain(difficulty=2)
    print(f"   Genesis block created")
    print(f"   Genesis hash: {blockchain.get_latest_block().hash}\n")
    
    # Add message blocks
    print("2. Adding Message Blocks:")
    block1 = blockchain.add_message_block(
        sender="alice",
        receiver="bob",
        ciphertext="a8f5c2d1e9b4...",
        message_hash="9b871c6d...",
        encryption_method="Caesar Cipher"
    )
    print(f"   Block 1 added - Hash: {block1.hash}")
    
    block2 = blockchain.add_message_block(
        sender="bob",
        receiver="alice",
        ciphertext="3e7f2a1c8d...",
        message_hash="4a6b8e2f...",
        encryption_method="XOR Stream Cipher"
    )
    print(f"   Block 2 added - Hash: {block2.hash}\n")
    
    # Verify blockchain
    print("3. Blockchain Validation:")
    is_valid, message = blockchain.is_chain_valid()
    print(f"   Valid: {is_valid}")
    print(f"   Message: {message}\n")
    
    # Get user messages
    print("4. Retrieve Alice's Messages:")
    alice_messages = blockchain.get_messages_for_user("alice")
    print(f"   Alice has {len(alice_messages)} message(s)")
    for block in alice_messages:
        print(f"   - Block {block.index}: {block.data['sender']} -> {block.data['receiver']}")
    print()
    
    # Display chain
    print("5. Blockchain Summary:")
    print(f"   Total blocks: {blockchain.get_chain_length()}")
    print(f"   Latest block index: {blockchain.get_latest_block().index}\n")
