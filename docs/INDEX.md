# Documentation Index

Welcome to the Secure Messaging System documentation!

## 📚 Table of Contents

### Getting Started
- **[Quick Start Guide](guides/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Installation](../README.md#installation)** - Setup and dependencies
- **[Project Structure](#project-structure)** - Understanding the codebase

### User Guides
- **[Network Mode Guide](guides/NETWORK_GUIDE.md)** - Multi-user client-server setup
- **[Standalone Mode](guides/QUICKSTART.md#standalone-mode)** - Single-user usage
- **[Storage Guide](guides/STORAGE.md)** - Data persistence and encryption
- **[Demo Guide](guides/DEMO_GUIDE.md)** - Presentation and demonstration

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
├── src/                          # Source code
│   ├── core/                     # Core cryptography modules
│   │   ├── authentication.py     # User authentication & sessions
│   │   ├── blockchain.py         # Blockchain with PoW
│   │   ├── classical_ciphers.py  # Caesar & Vigenère
│   │   ├── modern_ciphers.py     # XOR & Block ciphers
│   │   ├── hashing.py            # SHA-256 & HMAC
│   │   ├── elgamal.py            # ElGamal & KDC
│   │   ├── crypto_math.py        # Math primitives
│   │   └── storage.py            # Encrypted storage
│   │
│   └── network/                  # Network modules
│       ├── server.py             # Multi-user server
│       └── client.py             # Network client
│
├── scripts/                      # Launcher scripts
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
│   └── test_modern_ciphers.py
│
├── examples/                     # Example scripts
│   ├── demo_storage.py           # Storage demo
│   ├── test_storage.py           # Storage tests
│   └── verify_fix.py             # Verification
│
├── docs/                         # Documentation
│   ├── guides/                   # User guides
│   ├── api/                      # API reference
│   └── INDEX.md                  # This file
│
├── data/                         # Data storage (auto-created)
│   ├── .key                      # Encryption key
│   ├── users.json.enc            # Encrypted users
│   ├── user_keys.json.enc        # Encrypted keys
│   └── blockchain_temp.json      # Blockchain data
│
└── main.py                       # Standalone application
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
- Temporary persistence

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

**Purpose:** Classic encryption algorithms.

**Classes:**

**CaesarCipher** - Shift cipher
```python
caesar = CaesarCipher(shift=3)
ciphertext = caesar.encrypt("Hello World")
plaintext = caesar.decrypt(ciphertext)
```

**VigenereCipher** - Polyalphabetic cipher
```python
vigenere = VigenereCipher(key="SECRET")
ciphertext = vigenere.encrypt("Attack at Dawn")
plaintext = vigenere.decrypt(ciphertext)
```

---

### Modern Ciphers (`src/core/modern_ciphers.py`)

**Purpose:** Modern symmetric encryption.

**Classes:**

**XORStreamCipher** - XOR-based stream cipher
```python
xor = XORStreamCipher(key="SECRETKEY")
ciphertext = xor.encrypt("Secret message")
plaintext = xor.decrypt(ciphertext)
key_hex = xor.get_key_hex()
```

**MiniBlockCipher** - Simple block cipher
```python
block = MiniBlockCipher(key="BLOCKKEY")
ciphertext = block.encrypt("Confidential")
plaintext = block.decrypt(ciphertext)
```

---

### Hashing (`src/core/hashing.py`)

**Purpose:** Message integrity and authentication.

**Classes:**

**MessageIntegrity** - Hash operations
```python
# Compute hash
hash_value = MessageIntegrity.compute_hash("message")

# Verify hash
is_valid, computed = MessageIntegrity.verify_hash("message", hash_value)

# HMAC
hmac = MessageIntegrity.compute_hmac("message", "key")
is_valid, _ = MessageIntegrity.verify_hmac("message", "key", hmac)

# Multiple algorithms
hashes = MessageIntegrity.compute_multiple_hashes("message")
```

**MessageAuthenticationCode** - MAC handling
```python
mac_handler = MessageAuthenticationCode("shared_secret")
mac = mac_handler.generate_mac("message")
is_valid = mac_handler.verify_mac("message", mac)
```

---

### ElGamal & KDC (`src/core/elgamal.py`)

**Purpose:** Public key encryption and key distribution.

**Classes:**

**ElGamal** - Public key cryptography
```python
# Generate keys
keys = ElGamal.generate_keys(bits=16)

# Encrypt/Decrypt integers
ciphertext = ElGamal.encrypt(12345, keys)
plaintext = ElGamal.decrypt(ciphertext, keys)

# Encrypt/Decrypt strings
ciphertext = ElGamal.encrypt("Hi", keys)
plaintext = ElGamal.decrypt_to_string(ciphertext, keys)
```

**KeyDistributionCenter** - Centralized key management
```python
kdc = KeyDistributionCenter()

# Register user
kdc.register_user(username, key_pair)

# Get public key
public_key = kdc.get_public_key(username)

# Check registration
is_registered = kdc.is_user_registered(username)

# List users
users = kdc.list_registered_users()
```

---

### Cryptographic Math (`src/core/crypto_math.py`)

**Purpose:** Mathematical primitives for cryptography.

**Functions:**
```python
# GCD
result = gcd(48, 18)

# Modular inverse
inv = mod_inverse(3, 11)

# Modular exponentiation
result = power_mod(base, exp, mod)

# Prime testing
is_prime_num = is_prime(number)

# Prime generation
prime = generate_prime(bits=16)

# Primitive root
root = find_primitive_root(prime)
```

---

### Secure Storage (`src/core/storage.py`)

**Purpose:** Encrypted persistent data storage.

**Key Features:**
- Fernet encryption (AES-128)
- Auto-generated keys
- User data encryption
- ElGamal key encryption
- Blockchain persistence

**Main Methods:**
```python
storage = SecureStorage(data_dir="data")

# Save/Load users
storage.save_users(users_dict)
users = storage.load_users()

# Save/Load keys
storage.save_user_keys(keys_dict)
keys = storage.load_user_keys()

# Blockchain
storage.save_blockchain_temp(blockchain_data)
chain = storage.load_blockchain_temp()
storage.clear_blockchain_temp()

# Information
info = storage.get_storage_info()

# Backup
storage.backup_data()
```

---

## Usage Examples

### Basic Authentication Flow
```python
from src.core.storage import SecureStorage
from src.core.authentication import UserAuthentication

# Initialize with storage
storage = SecureStorage()
auth = UserAuthentication(storage=storage)

# Register
success, msg = auth.register_user("alice", "password123", "alice@example.com")

# Login
success, msg = auth.login("alice", "password123")
session_id = msg.split(": ")[1] if success else None

# Data persists across restarts!
```

### Encrypt and Store Message
```python
from src.core.classical_ciphers import CaesarCipher
from src.core.hashing import MessageIntegrity
from src.core.blockchain import MessageBlockchain
from src.core.storage import SecureStorage

# Initialize
storage = SecureStorage()
blockchain = MessageBlockchain(difficulty=2, storage=storage)
cipher = CaesarCipher(shift=3)

# Encrypt
plaintext = "Secret Message"
ciphertext = cipher.encrypt(plaintext)
msg_hash = MessageIntegrity.compute_hash(plaintext)

# Store in blockchain
block = blockchain.add_message_block(
    sender="alice",
    receiver="bob",
    ciphertext=ciphertext,
    message_hash=msg_hash,
    encryption_method="Caesar Cipher"
)

# Blockchain persists temporarily!
```

### ElGamal Key Exchange
```python
from src.core.elgamal import ElGamal, KeyDistributionCenter

# Setup KDC
kdc = KeyDistributionCenter()

# Alice generates keys
alice_keys = ElGamal.generate_keys(bits=16)
kdc.register_user("alice", alice_keys)

# Bob generates keys
bob_keys = ElGamal.generate_keys(bits=16)
kdc.register_user("bob", bob_keys)

# Alice gets Bob's public key
bob_public = kdc.get_public_key("bob")

# Alice encrypts for Bob
message = 12345
ciphertext = ElGamal.encrypt(message, bob_public)

# Bob decrypts with his private key
decrypted = ElGamal.decrypt(ciphertext, bob_keys)
```

---

## Quick Command Reference

```bash
# Run server
python scripts/run_server.py

# Run client
python scripts/run_client.py

# Standalone mode
python scripts/run_standalone.py

# Run all tests
python tests/run_tests.py

# Storage demo
python examples/demo_storage.py

# Verify system
python examples/verify_fix.py
```

---

## Security Features Summary

| Feature | Module | Encryption | Persistence |
|---------|--------|------------|-------------|
| User Authentication | `authentication.py` | SHA-256 Hash | ✓ Encrypted |
| User Sessions | `authentication.py` | - | ✗ Memory only |
| ElGamal Keys | `elgamal.py` | - | ✓ Encrypted |
| Blockchain | `blockchain.py` | - | ✓ Temporary |
| Storage Encryption | `storage.py` | Fernet/AES-128 | ✓ Files |
| Message Hashing | `hashing.py` | SHA-256 | - |
| Message Encryption | `*_ciphers.py` | Various | - |

---

## Next Steps

1. **New User?** → Start with [Quick Start Guide](guides/QUICKSTART.md)
2. **Developer?** → Read [Architecture](api/ARCHITECTURE.md)
3. **Testing?** → See [Testing Guide](api/TESTING.md)
4. **Presenting?** → Use [Demo Guide](guides/DEMO_GUIDE.md)

---

**Need Help?** Check the specific guides or contact the maintainer.
