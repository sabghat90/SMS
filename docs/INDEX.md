# Documentation Index

Welcome to the Secure Messaging System documentation!

## Table of Contents

### Getting Started
- **[Quick Start Guide](guides/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Installation](../README.md#installation)** - Setup and dependencies
- **[Project Structure](#project-structure)** - Understanding the codebase

### User Guides
- **[Network Mode Guide](guides/NETWORK_GUIDE.md)** - Multi-user client-server setup
- **[Standalone Mode](guides/QUICKSTART.md)** - Single-user usage
- **[Storage Guide](guides/STORAGE.md)** - Data persistence and encryption
- **[Demo Guide](guides/DEMO_GUIDE.md)** - Presentation and demonstration

### Advanced Lab Guides (Labs 12-15)
- **[Lab 12: Diffie-Hellman Key Exchange](guides/LAB12.md)** - Establishing shared secrets
- **[Lab 13: AEAD](guides/LAB13.md)** - Authenticated encryption with associated data
- **[Lab 14: Key Management](guides/LAB14.md)** - Key lifecycle, rotation, revocation
- **[Lab 15: Post-Quantum & Forward Secrecy](guides/LAB15.md)** - Quantum-resistant crypto and ephemeral keys

### API Reference
- **[Architecture](api/ARCHITECTURE.md)** - System design and components
- **[Lab Mapping](api/LAB_MAPPING.md)** - Security concepts integration
- **[Testing Guide](api/TESTING.md)** - Running and writing tests
- **[Core Modules](#core-modules-api)** - Cryptography APIs

### Examples
- **[Example Scripts](../examples/)** - Demo and test scripts
- **[Usage Examples](#usage-examples)** - Common use cases

---

## Project Structure

```
SMS/
├── main.py                       # Standalone application
├── server.py                     # Network server (easy access)
├── client.py                     # Network client (easy access)
│
├── src/                          # Source code
│   ├── core/                     # Core cryptography modules
│   │   ├── authentication.py     # User authentication & sessions
│   │   ├── blockchain.py         # Blockchain with PoW
│   │   ├── classical_ciphers.py  # Caesar & Vigenère
│   │   ├── modern_ciphers.py     # XOR & Block ciphers
│   │   ├── hashing.py            # SHA-256 & HMAC
│   │   ├── elgamal.py            # ElGamal & KDC
│   │   ├── crypto_math.py        # Math primitives
│   │   ├── storage.py            # Encrypted storage
│   │   ├── security_utils.py     # Security helpers
│   │   ├── lab12_key_exchange.py # Diffie-Hellman (Lab 12)
│   │   ├── lab13_aead.py         # AEAD (Lab 13)
│   │   ├── lab14_km.py           # Key Management (Lab 14)
│   │   └── lab15_postquantum.py  # Post-Quantum & Forward Secrecy (Lab 15)
│   │
│   └── network/                  # Network modules
│       ├── server.py             # Multi-user server
│       └── client.py             # Network client
│
├── scripts/                      # Launcher scripts (legacy)
│   ├── run_server.py             # Start server
│   ├── run_client.py             # Start client
│   └── run_standalone.py         # Standalone mode
│
├── tests/                        # Unit tests
│   ├── test_authentication.py
│   ├── test_blockchain.py
│   ├── test_classical_ciphers.py
│   ├── test_crypto_math.py
│   ├── test_hashing.py
│   ├── test_modern_ciphers.py
│   ├── test_lab_concepts.py
│   ├── test_lab12.py             # Lab 12 tests
│   ├── test_lab13.py             # Lab 13 tests
│   ├── test_lab14.py             # Lab 14 tests
│   └── test_lab15.py             # Lab 15 tests
│
├── examples/                     # Example scripts
│   ├── demo_storage.py           # Storage demo
│   ├── test_storage.py           # Storage tests
│   ├── verify_fix.py             # Verification
│   ├── demo_lab12.py             # DH key exchange demo
│   ├── demo_lab13.py             # AEAD demo
│   ├── demo_lab14.py             # Key management demo
│   └── demo_lab15.py             # Post-quantum & forward secrecy demo
│
├── docs/                         # Documentation
│   ├── guides/                   # User guides
│   ├── api/                      # API reference
│   └── INDEX.md                  # This file
│
└── data/                         # Data storage (auto-created)
    ├── users.json.enc            # Encrypted users
    ├── user_keys.json.enc        # Encrypted keys
    └── blockchain_temp.json      # Blockchain data
```

---

## Core Modules API

### Authentication (`src/core/authentication.py`)

**Purpose:** User registration, login, and session management with encrypted storage.

**Key Features:**
- Password hashing (SHA-256)
- Session management
- User data encryption
- Persistent storage

**Main Methods:**
```python
auth = UserAuthentication(storage=SecureStorage())

# Register user
success, msg = auth.register_user(username, password, email)

# Login
success, msg = auth.login(username, password)

# Session management
auth.logout(session_id)
is_active = auth.is_session_active(session_id)

# User info
info = auth.get_user_info(username)
users = auth.list_users()

# Change password
success, msg = auth.change_password(username, old_pass, new_pass)
```

---

### Blockchain (`src/core/blockchain.py`)

**Purpose:** Immutable message ledger with Proof-of-Work mining.

**Key Features:**
- Genesis block creation
- PoW mining
- Chain validation
- Message logging
- Persistent storage

**Main Methods:**
```python
blockchain = MessageBlockchain(difficulty=2, storage=SecureStorage())

# Add message block
block = blockchain.add_message_block(
    sender="alice",
    receiver="bob",
    ciphertext="encrypted",
    message_hash="hash",
    encryption_method="Caesar"
)

# Validate chain
is_valid, msg = blockchain.is_chain_valid()

# Query messages
messages = blockchain.get_messages_for_user(username)
block = blockchain.get_block_by_index(index)

# Chain info
length = blockchain.get_chain_length()
latest = blockchain.get_latest_block()
```

---

### Classical Ciphers (`src/core/classical_ciphers.py`)

**Purpose:** Caesar and Vigenère cipher implementations.

**Caesar Cipher:**
```python
cipher = CaesarCipher(shift=5)
encrypted = cipher.encrypt("HELLO")  # "MJQQT"
decrypted = cipher.decrypt("MJQQT")  # "HELLO"
```

**Vigenère Cipher:**
```python
cipher = VigenereCipher(key="SECRET")
encrypted = cipher.encrypt("HELLO")
decrypted = cipher.decrypt(encrypted)
```

---

### Modern Ciphers (`src/core/modern_ciphers.py`)

**Purpose:** XOR stream cipher and Mini block cipher.

**XOR Stream Cipher:**
```python
cipher = XORStreamCipher(key_hex="a1b2c3d4...")
encrypted = cipher.encrypt("Secret message")
decrypted = cipher.decrypt(encrypted)

# Or generate random key
cipher = XORStreamCipher.generate_random_key(length=16)
```

**Mini Block Cipher:**
```python
cipher = MiniBlockCipher(key_hex="0123456789abcdef")
encrypted = cipher.encrypt("12345678")  # 8-byte blocks
decrypted = cipher.decrypt(encrypted)
```

---

### Hashing (`src/core/hashing.py`)

**Purpose:** SHA-256 hashing and HMAC for integrity.

**Main Features:**
```python
# Compute hash
hash_value = MessageIntegrity.compute_hash("message")

# Compute HMAC
hmac_value = MessageIntegrity.compute_hmac("data", "secret_key")

# Verify hash
is_valid = MessageIntegrity.verify_hash("message", expected_hash)

# Verify HMAC
is_valid = MessageIntegrity.verify_hmac("data", "key", expected_hmac)
```

---

### ElGamal (`src/core/elgamal.py`)

**Purpose:** Public key cryptography and Key Distribution Center.

**ElGamal Encryption:**
```python
# Generate keys
key_pair = ElGamal.generate_keys(bits=16)

# Encrypt
c1, c2 = ElGamal.encrypt("Hello", key_pair.p, key_pair.g, key_pair.public_key)

# Decrypt
plaintext = ElGamal.decrypt(c1, c2, key_pair.p, key_pair.private_key)
```

**Key Distribution Center:**
```python
kdc = KeyDistributionCenter()

# Register user
kdc.register_user("alice", alice_key_pair)

# Get public key
public_key = kdc.get_public_key("alice")
```

---

### Storage (`src/core/storage.py`)

**Purpose:** Encrypted data persistence with XOR + HMAC.

**Main Features:**
```python
storage = SecureStorage(data_dir="data")

# Save/load users (encrypted)
storage.save_users(users_dict)
users = storage.load_users()

# Save/load user keys (encrypted)
storage.save_user_keys(keys_dict)
keys = storage.load_user_keys()

# Save/load blockchain
storage.save_blockchain(blockchain_data)
chain = storage.load_blockchain()
```

---

## Quick Start Commands

### Standalone Mode
```bash
# Run single-user application
python main.py
```

### Network Mode
```bash
# Terminal 1: Start server
python server.py

# Terminal 2+: Start clients
python client.py
```

### Testing
```bash
# Run all tests
python tests/run_tests.py

# Test specific module
python tests/test_authentication.py

# Verify lab concepts
python tests/test_lab_concepts.py
```

---

## Usage Examples

### Example 1: Basic Messaging (Standalone)
```python
from src.core.authentication import UserAuthentication
from src.core.classical_ciphers import CaesarCipher
from src.core.hashing import MessageIntegrity
from src.core.blockchain import MessageBlockchain
from src.core.storage import SecureStorage

# Setup
storage = SecureStorage()
auth = UserAuthentication(storage=storage)
blockchain = MessageBlockchain(difficulty=2, storage=storage)

# Register users
auth.register_user("alice", "pass123", "alice@example.com")
auth.register_user("bob", "pass456", "bob@example.com")

# Encrypt message
cipher = CaesarCipher(shift=5)
message = "Secret meeting"
ciphertext = cipher.encrypt(message)
msg_hash = MessageIntegrity.compute_hash(message)

# Add to blockchain
blockchain.add_message_block(
    sender="alice",
    receiver="bob",
    ciphertext=ciphertext,
    message_hash=msg_hash,
    encryption_method="Caesar"
)

# Verify blockchain
is_valid, msg = blockchain.is_chain_valid()
print(f"Blockchain valid: {is_valid}")
```

### Example 2: ElGamal Encryption
```python
from src.core.elgamal import ElGamal, KeyDistributionCenter

# Generate keys for alice
alice_keys = ElGamal.generate_keys(bits=16)

# Generate keys for bob
bob_keys = ElGamal.generate_keys(bits=16)

# Setup KDC
kdc = KeyDistributionCenter()
kdc.register_user("alice", alice_keys)
kdc.register_user("bob", bob_keys)

# Alice sends to Bob
message = "Top Secret"
bob_public = kdc.get_public_key("bob")
c1, c2 = ElGamal.encrypt(message, bob_keys.p, bob_keys.g, bob_public)

# Bob decrypts
plaintext = ElGamal.decrypt(c1, c2, bob_keys.p, bob_keys.private_key)
print(f"Decrypted: {plaintext}")
```

### Example 3: Secure Storage
```python
from src.core.storage import SecureStorage

storage = SecureStorage(data_dir="data")

# Save data (automatically encrypted with XOR + HMAC)
users = {
    "alice": {"password": "hashed", "email": "alice@example.com"},
    "bob": {"password": "hashed", "email": "bob@example.com"}
}
storage.save_users(users)

# Load data (automatically decrypted and verified)
loaded_users = storage.load_users()
print(f"Loaded {len(loaded_users)} users")
```

---

## Security Features Summary

### Data Protection
- **At Rest**: XOR encryption + HMAC integrity
- **In Transit**: Encrypted before network transmission
- **Passwords**: SHA-256 hashed
- **Keys**: Securely generated and stored

### Cryptographic Methods
1. **Caesar Cipher** - Classical substitution
2. **Vigenère Cipher** - Polyalphabetic substitution
3. **XOR Stream Cipher** - Modern stream encryption
4. **Mini Block Cipher** - Block-based encryption
5. **ElGamal** - Public key cryptography

### Integrity Verification
- **SHA-256 Hashing** - Message integrity
- **HMAC** - Authenticated encryption
- **Blockchain** - Tamper-evident ledger
- **PoW Mining** - Computational proof

---

## Lab Concepts Mapping

| Lab | Concept | Implementation |
|-----|---------|----------------|
| 01-02 | Python Basics | All modules |
| 03 | Caesar Cipher | `classical_ciphers.py` |
| 04 | Vigenère Cipher | `classical_ciphers.py` |
| 05 | Modern Ciphers | `modern_ciphers.py` + `storage.py` |
| 06 | Hashing & HMAC | `hashing.py` + `storage.py` |
| 07 | Blockchain | `blockchain.py` |
| 09 | ElGamal | `elgamal.py` |
| 11 | KDC | `elgamal.py` |

---

## Additional Resources

### Documentation Files
- [Quick Start](guides/QUICKSTART.md) - 5-minute tutorial
- [Network Guide](guides/NETWORK_GUIDE.md) - Multi-user setup
- [Architecture](api/ARCHITECTURE.md) - System design
- [Lab Mapping](api/LAB_MAPPING.md) - Detailed lab concepts
- [Testing Guide](api/TESTING.md) - Test suite documentation

### Example Scripts
- `examples/demo_storage.py` - Storage demonstration
- `examples/test_storage.py` - Storage testing
- `examples/verify_fix.py` - System verification

### Main Application Files
- `main.py` - Standalone messaging application
- `server.py` - Network server (simplified access)
- `client.py` - Network client (simplified access)

---

## Support

For issues, questions, or contributions:
- See the main [README](../README.md)
- Check [GitHub Issues](https://github.com/sabghat90/SMS/issues)
- Review example scripts in `examples/`

---

**Happy Learning!** Start with the [Quick Start Guide](guides/QUICKSTART.md)
