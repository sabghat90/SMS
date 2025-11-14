# Lab 07 - Blockchain and Message Logging

## Overview

Lab 07 demonstrates blockchain technology for secure, immutable message logging. Each message is stored as a block in a chain, providing non-repudiation and tamper detection.

**Module**: `src/core/blockchain.py`

## Blockchain Concepts

### What is a Blockchain?

A blockchain is a distributed ledger consisting of blocks of data that are:
- **Linked**: Each block contains the hash of the previous block
- **Immutable**: Changing any block invalidates all subsequent blocks
- **Transparent**: All transactions are visible and verifiable
- **Decentralized**: No single point of control or failure

### Key Components

1. **Block**: Container for transaction data
2. **Hash**: Unique fingerprint of block contents
3. **Previous Hash**: Links to previous block
4. **Timestamp**: When block was created
5. **Nonce**: Number used once (for Proof of Work)

## Implementation Details

### Block Structure

```python
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index          # Position in chain
        self.timestamp = timestamp  # Creation time
        self.data = data           # Message/transaction data
        self.previous_hash = previous_hash  # Link to previous block
        self.nonce = 0             # For mining
        self.hash = self.calculate_hash()
```

### Blockchain Class

```python
class MessageBlockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 2  # Mining difficulty
```

## API Reference

### Block Methods

```python
class Block:
    def calculate_hash(self) -> str
    def mine_block(self, difficulty: int = 2) -> None
    def to_dict(self) -> dict
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Block'
```

### Blockchain Methods

```python
class MessageBlockchain:
    def create_genesis_block(self) -> Block
    def get_latest_block(self) -> Block
    def add_message_block(self, sender: str, recipient: str, 
                         message: str, cipher_type: str, 
                         encrypted: bool = True) -> Block
    def is_chain_valid(self) -> bool
    def save_to_file(self, filename: str) -> None
    def load_from_file(self, filename: str) -> bool
    def display_chain(self) -> None
    def get_user_messages(self, username: str) -> list
```

## Usage Examples

### Creating and Using Blockchain

```python
from src.core.blockchain import MessageBlockchain

# Create new blockchain
blockchain = MessageBlockchain()

# Add message blocks
block1 = blockchain.add_message_block(
    sender="alice",
    recipient="bob", 
    message="Hello Bob!",
    cipher_type="caesar"
)

block2 = blockchain.add_message_block(
    sender="bob",
    recipient="alice",
    message="Hi Alice!",
    cipher_type="vigenere"
)

# Verify chain integrity
is_valid = blockchain.is_chain_valid()
print(f"Blockchain valid: {is_valid}")

# Display entire chain
blockchain.display_chain()
```

### Message Data Structure

Each block contains message data:

```python
{
    "sender": "alice",
    "recipient": "bob",
    "message": "encrypted_message_here",
    "cipher_type": "caesar",
    "encrypted": True,
    "timestamp": "2024-01-01 12:00:00"
}
```

## Proof of Work Mining

### Concept

**Proof of Work** requires computational effort to create valid blocks, making tampering expensive.

### Mining Process

1. Start with nonce = 0
2. Calculate block hash
3. Check if hash starts with required number of zeros
4. If not, increment nonce and repeat
5. When found, block is "mined"

### Mining Example

```python
# Mine a block with difficulty 3 (hash must start with "000")
block = blockchain.get_latest_block()
block.mine_block(difficulty=3)

print(f"Block mined! Hash: {block.hash}")
print(f"Nonce used: {block.nonce}")
# Example output: Hash: 000abc123... Nonce: 1847
```

### Difficulty Adjustment

Higher difficulty = more security but slower mining:
- Difficulty 1: Hash starts with "0" (easy)
- Difficulty 4: Hash starts with "0000" (hard)
- Difficulty 6: Hash starts with "000000" (very hard)

## Security Properties

### Immutability

Changing any block breaks the chain:

```python
# Tamper with a block
blockchain.chain[1].data["message"] = "TAMPERED MESSAGE"

# Recalculate hash (attacker would do this)
blockchain.chain[1].hash = blockchain.chain[1].calculate_hash()

# Validation fails because previous_hash links are broken
is_valid = blockchain.is_chain_valid()
print(f"Valid after tampering: {is_valid}")  # False
```

### Non-Repudiation

Once a message is in the blockchain:
1. Sender cannot deny sending it (digital signature in real blockchains)
2. Timestamp proves when it was sent
3. Immutability prevents modification
4. Public ledger provides transparency

## Integration with SMS

### Message Logging

```python
# Every message sent is logged to blockchain
def send_message(self, recipient, message, cipher_type="caesar"):
    # Encrypt message
    encrypted_msg = self.encrypt_message(message, cipher_type)
    
    # Log to blockchain
    block = self.blockchain.add_message_block(
        sender=self.current_user,
        recipient=recipient,
        message=encrypted_msg,
        cipher_type=cipher_type
    )
    
    # Save blockchain
    self.blockchain.save_to_file("blockchain_messages.json")
    
    return block
```

### Message History

```python
# Get all messages for a user
alice_messages = blockchain.get_user_messages("alice")

for msg in alice_messages:
    print(f"From: {msg['sender']}")
    print(f"To: {msg['recipient']}")
    print(f"Message: {msg['message']}")
    print(f"Time: {msg['timestamp']}")
    print("---")
```

## Persistence

### Saving Blockchain

```python
# Save to file
blockchain.save_to_file("my_blockchain.json")

# Load from file
new_blockchain = MessageBlockchain()
success = new_blockchain.load_from_file("my_blockchain.json")
if success:
    print("Blockchain loaded successfully")
```

### File Format

Blockchain saved as JSON:

```json
[
    {
        "index": 0,
        "timestamp": "2024-01-01 00:00:00",
        "data": "Genesis Block",
        "previous_hash": "0",
        "nonce": 0,
        "hash": "abc123..."
    },
    {
        "index": 1,
        "timestamp": "2024-01-01 12:00:00",
        "data": {
            "sender": "alice",
            "recipient": "bob",
            "message": "Hello Bob!",
            "cipher_type": "caesar"
        },
        "previous_hash": "abc123...",
        "nonce": 42,
        "hash": "def456..."
    }
]
```

## Real-World Comparison

| Feature | SMS Blockchain | Bitcoin | Ethereum |
|---------|---------------|---------|----------|
| **Purpose** | Message logging | Digital currency | Smart contracts |
| **Block Size** | Variable | ~1MB | Variable |
| **Block Time** | Instant | ~10 minutes | ~15 seconds |
| **Consensus** | Simple PoW | SHA-256 PoW | Proof of Stake |
| **Network** | Centralized | Decentralized | Decentralized |

## Testing

```python
def test_blockchain():
    """Test blockchain functionality"""
    blockchain = MessageBlockchain()
    
    # Test genesis block
    assert len(blockchain.chain) == 1
    assert blockchain.chain[0].index == 0
    
    # Add message block
    block = blockchain.add_message_block("alice", "bob", "test", "caesar")
    assert len(blockchain.chain) == 2
    assert block.index == 1
    
    # Test chain validation
    assert blockchain.is_chain_valid()
    
    # Test tampering detection
    blockchain.chain[1].data["message"] = "tampered"
    blockchain.chain[1].hash = blockchain.chain[1].calculate_hash()
    assert not blockchain.is_chain_valid()
    
    print("Blockchain tests passed")

test_blockchain()
```

## Limitations of Simple Blockchain

This implementation is educational. Production blockchains need:

1. **Distributed Network**: Multiple nodes, consensus protocols
2. **Digital Signatures**: Cryptographic proof of message authorship
3. **Advanced Consensus**: Proof of Stake, Byzantine Fault Tolerance
4. **Scalability**: Sharding, layer 2 solutions
5. **Privacy**: Zero-knowledge proofs, mixing
6. **Governance**: On-chain voting, upgrade mechanisms

## Further Reading

- "Mastering Bitcoin" by Andreas Antonopoulos
- "Blockchain Basics" by Daniel Drescher  
- "Building Ethereum DApps" by Roberto Infante
- Study Bitcoin whitepaper by Satoshi Nakamoto
- Learn about smart contracts and decentralized applications (DApps)
- Explore consensus algorithms: PoW, PoS, PBFT, Raft

## Real-World Use Cases

### Blockchain Applications
- **Cryptocurrencies**: Bitcoin, Ethereum, Litecoin
- **Supply Chain**: Walmart food tracing, diamond certification
- **Identity**: Self-sovereign identity, digital credentials
- **Voting**: Transparent, verifiable elections
- **Healthcare**: Secure, shared medical records
- **Real Estate**: Property title management
- **Gaming**: Non-fungible tokens (NFTs), virtual assets