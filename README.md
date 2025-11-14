# Secure Messaging System (SMS)

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Lab Concepts](https://img.shields.io/badge/Lab%20Concepts-Labs%201--15-success.svg)](docs/api/LAB_MAPPING.md)
[![Security](https://img.shields.io/badge/Security-DH%20%2B%20AEAD%20%2B%20Forward%20Secrecy-orange.svg)](docs/guides/SECURE_COMMUNICATION.md)
[![No Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)](requirements.txt)

> A comprehensive cryptographic messaging system implementing **all lab concepts** from Computer Security (Labs 01-15). This educational project demonstrates practical applications of classical ciphers, modern cryptography, blockchain technology, and **secure communication protocols** - without using any external cryptography libraries!

---

## 🆕 NEW: Labs 12-15 Secure Communication Protocol

**Production-grade security features now integrated!**
- 🔐 **Lab 12**: Diffie-Hellman key exchange for secure session establishment
- 🔐 **Lab 13**: AEAD (Authenticated Encryption) for confidentiality + integrity
- 🔐 **Lab 14**: Automatic key rotation and lifecycle management
- 🔐 **Lab 15**: Forward secrecy with ephemeral keys

👉 **[Quick Start Guide](QUICKSTART_SECURE.md)** | **[Try Interactive Demo](#secure-communication-demo)**

---

## Highlights

- **Pure Lab Concepts** - No external crypto libraries, Labs 01-15 implementations  
- **Production-Grade Security** - DH key exchange + AEAD + Forward Secrecy (Labs 12-15)
- **Multi-Layer Protection** - XOR encryption + HMAC integrity + SHA-256 hashing  
- **Blockchain Ledger** - Immutable message history with Proof of Work  
- **Network Ready** - Multi-user client-server architecture with secure protocol
- **Persistent Storage** - Encrypted data at rest with integrity verification  
- **Fully Tested** - Comprehensive test suite with 100% lab concept coverage
- **Interactive Demos** - Real-time demonstrations of all security concepts

---

## Quick Start

### Prerequisites
- **Python 3.7+** (No additional packages needed!)

### Installation

```bash
# Clone the repository
git clone https://github.com/sabghat90/SMS.git
cd SMS

# No pip install needed! Uses only Python standard library + lab concepts
```

### Run Modes

#### 1. 🆕 Secure Communication Demo (Labs 12-15) ⭐
```bash
# Interactive demonstration of all security concepts
python demo_secure_communication.py
```
**What you'll see**: DH key exchange, AEAD encryption, key rotation, forward secrecy

#### 2. 🆕 Secure Client-Server (Production-Grade Security) ⭐
```bash
# Terminal 1: Start Secure Server (port 5556)
python secure_server.py

# Terminal 2: Start Secure Client (Alice)
python secure_client.py

# Terminal 3: Start Secure Client (Bob)
python secure_client.py
```
**Features**: Automatic DH handshake, AEAD encryption, key rotation, forward secrecy

#### 3. Original Client-Server (Basic Security)
```bash
# Terminal 1: Start Server (port 5555)
python server.py

# Terminal 2: Start Client
python client.py
```
**Features**: Classical & modern ciphers, blockchain, basic encryption

#### 4. Standalone Mode (Single User)
```bash
python main.py
```

#### 5. Run Tests
```bash
# Test all labs 12-15
python tests/test_lab12.py
python tests/test_lab13.py
python tests/test_lab14.py
python tests/test_lab15.py

# Run all tests
python tests/run_tests.py
```

---

## Lab Concepts Implementation

This project demonstrates **all 11 labs** in action:

| Lab | Concept | Module | Real Application |
|-----|---------|--------|------------------|
| **01** | Python Basics | All modules | Functions, variables, control structures |
| **02** | Collections (Dict) | `authentication.py` | User storage, session management |
| **03** | Caesar Cipher | `classical_ciphers.py` | Classical encryption |
| **04** | Vigenère Cipher | `classical_ciphers.py` | Polyalphabetic encryption |
| **05** | Modern Ciphers | `modern_ciphers.py` | **XOR Stream Cipher** for data encryption |
| **06** | Hashing & HMAC | `hashing.py` | **SHA-256 + HMAC** for integrity |
| **07** | Blockchain | `blockchain.py` | Message ledger with PoW |
| **09** | ElGamal | `elgamal.py` | Public key cryptography |
| **11** | Key Distribution | `elgamal.py` | KDC implementation |
| **12** | Key Exchange | `lab12_key_exchange.py` | **Diffie-Hellman** for session keys |
| **13** | AEAD | `lab13_aead.py` | **Authenticated Encryption** (confidentiality + integrity) |
| **14** | Key Management | `lab14_km.py` | Key rotation, revocation, lifecycle |
| **15** | Post-Quantum/Forward Secrecy | `lab15_postquantum.py` | Ephemeral keys, quantum-resistant crypto |

**Detailed mapping**: [LAB_MAPPING.md](docs/api/LAB_MAPPING.md)

---

## Security Architecture

### Storage Security (Labs 05 + 06)

```
┌─────────────────────────────────────────────────────────────┐
│                   SECURE STORAGE FLOW                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Master Password                                            │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────┐                                        │
│  │ SHA-256 (Lab 06)│──► Encryption Key (128-bit)           │
│  └─────────────────┘                                        │
│                                                             │
│  User Data (JSON)                                           │
│       │                                                     │
│       ▼                                                     │
│  ┌─────────────────────┐                                    │
│  │ XOR Cipher (Lab 05) │──► Encrypted Data                 │
│  └─────────────────────┘                                    │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────────────────┐                                   │
│  │ HMAC-SHA256 (Lab 06) │──► Integrity Signature           │
│  └──────────────────────┘                                   │
│       │                                                     │
│       ▼                                                     │
│  Save: {encrypted: ..., hmac: ...}                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Message Flow with Blockchain

```
Send Message ──► Choose Cipher ──► Encrypt ──► Hash (SHA-256)
                                        │            │
                                        ▼            ▼
                                   Ciphertext   Message Hash
                                        │            │
                                        └────┬───────┘
                                             │
                                             ▼
                                    Create Block with:
                                    - Sender/Receiver
                                    - Ciphertext
                                    - Hash
                                    - Previous Block Hash
                                             │
                                             ▼
                                      Mine Block (PoW)
                                             │
                                             ▼
                                     Add to Blockchain
                                             │
                                             ▼
                                    Save to Storage (HMAC protected)
```

---

## Project Structure

```
SMS/
├── main.py                        # Standalone application entry point
├── server.py                      # Network server (easy access)
├── client.py                      # Network client (easy access)
├── requirements.txt               # Dependencies (NONE - only standard lib!)
├── README.md                      # This file
│
├── src/                           # Source code
│   ├── core/                      # Core cryptography modules
│   │   ├── authentication.py      # User auth & sessions (Lab 02)
│   │   ├── blockchain.py          # Blockchain with PoW (Lab 07)
│   │   ├── classical_ciphers.py   # Caesar, Vigenère (Lab 03-04)
│   │   ├── modern_ciphers.py      # XOR, Block Cipher (Lab 05)
│   │   ├── hashing.py             # SHA-256, HMAC (Lab 06)
│   │   ├── elgamal.py             # ElGamal, KDC (Lab 09, 11)
│   │   ├── crypto_math.py         # Math primitives (primes, modular)
│   │   ├── storage.py             # Encrypted storage (Lab 05+06)
│   │   └── security_utils.py      # Security helpers (Lab concepts)
│   │
│   └── network/                   # Network modules
│       ├── server.py              # Multi-user TCP server
│       └── client.py              # Network client
│
├── scripts/                       # Launcher scripts (legacy)
│   ├── run_server.py              # Start network server
│   ├── run_client.py              # Start network client
│   └── run_standalone.py          # Start standalone mode
│
├── tests/                         # Unit tests
│   ├── test_authentication.py     # Auth tests
│   ├── test_blockchain.py         # Blockchain tests
│   ├── test_classical_ciphers.py  # Classical cipher tests
│   ├── test_crypto_math.py        # Crypto math tests
│   ├── test_hashing.py            # Hashing tests
│   ├── test_modern_ciphers.py     # Modern cipher tests
│   ├── test_lab_concepts.py       # Lab concepts verification
│   ├── run_tests.py               # Test runner
│   └── README.md                  # Testing guide
│
├── examples/                      # Example & demo scripts
│   ├── demo_storage.py            # Storage demonstration
│   ├── test_storage.py            # Storage integration tests
│   └── verify_fix.py              # System verification
│
├── docs/                          # Documentation
│   ├── INDEX.md                   # Documentation hub
│   ├── LAB_CONCEPTS_IMPLEMENTATION.md  # Lab concepts summary
│   ├── REORGANIZATION_SUMMARY.md  # Project reorganization notes
│   │
│   ├── guides/                    # User guides
│   │   ├── QUICKSTART.md          # 5-minute setup
│   │   ├── NETWORK_GUIDE.md       # Multi-user guide
│   │   ├── STORAGE_LAB_CONCEPTS.md # Storage security details
│   │   ├── STORAGE_IMPLEMENTATION.md # Storage implementation
│   │   ├── DEMO_GUIDE.md          # Presentation guide
│   │   └── DATA_DIRECTORY_FIX.md  # Troubleshooting
│   │
│   └── api/                       # API reference
│       ├── ARCHITECTURE.md        # System architecture
│       ├── LAB_MAPPING.md         # Lab concepts mapping
│       └── TESTING.md             # Testing guide
│
└── data/                          # Auto-created data directory
    ├── users.json.enc             # Encrypted user data (XOR + HMAC)
    ├── user_keys.json.enc         # Encrypted ElGamal keys (XOR + HMAC)
    ├── .integrity                 # SHA-256 integrity hashes
    └── blockchain_temp.json       # Blockchain storage (SHA-256 protected)
```

---

## Core Features

### 1. User Authentication (Lab 02, 06)
- Secure registration with SHA-256 password hashing
- Session management with hash-based session IDs
- Login/logout functionality
- Password change capability

### 2. Encryption Methods

#### Classical Ciphers (Lab 03-04)
- **Caesar Cipher**: Character shifting with modular arithmetic
- **Vigenère Cipher**: Keyword-based polyalphabetic substitution

#### Modern Ciphers (Lab 05)
- **XOR Stream Cipher**: Keystream generation + XOR encryption
- **Mini Block Cipher**: Substitution-Permutation Network (SPN)

#### Public Key Cryptography (Lab 09)
- **ElGamal Encryption**: Asymmetric encryption/decryption
- **Key Generation**: Prime generation, primitive roots
- **Key Distribution Center**: Centralized key management

### 3. Message Integrity (Lab 06)
- **SHA-256 Hashing**: Pre-encryption message hashing
- **HMAC Verification**: Message authentication codes
- **Hash Comparison**: Post-decryption integrity check

### 4. Blockchain (Lab 07)
- **Block Structure**: Index, timestamp, data, previous hash, nonce
- **Proof of Work**: Mining with difficulty adjustment
- **Chain Validation**: Cryptographic verification
- **Immutable Ledger**: Tamper-evident message history

### 5. Secure Storage (Lab 05 + 06)
- **XOR Encryption**: Data at rest protection
- **HMAC Integrity**: Tamper detection
- **SHA-256 Hashing**: File integrity verification
- **Key Derivation**: Secure key generation from password

### 6. Network Communication
- **TCP/IP Server**: Multi-threaded client handling
- **Client Protocol**: Command-based interaction
- **KDC Integration**: Centralized key lookup
- **Concurrent Users**: Multiple simultaneous connections

---

## Usage Examples

### Example 1: Standalone Mode - Send Encrypted Message

```bash
# Start application
python main.py

# Register/Login
# Choose encryption method (e.g., ElGamal)
# Send message - automatically:
#   1. Encrypts with chosen cipher
#   2. Computes SHA-256 hash
#   3. Adds to blockchain with PoW
#   4. Saves encrypted (XOR + HMAC)
```

### Example 2: Network Mode - Multi-User Chat

```bash
# Terminal 1: Server
python server.py
# Server starts with demo users (alice, bob, charlie)

# Terminal 2: Client 1 (Alice)
python client.py
# Login as alice
# Send encrypted message to bob

# Terminal 3: Client 2 (Bob)
python client.py
# Login as bob
# View messages from alice
# Decrypt and verify integrity
```

### Example 3: Verify Lab Concepts

```bash
# Run comprehensive verification
python tests/test_lab_concepts.py

# Output shows:
# - Lab 05: XOR Stream Cipher working
# - Lab 06: SHA-256 + HMAC working
# - Lab 09: Prime generation working
# - All security using lab concepts only
```

---

## Testing

### Run All Tests

```bash
# Unit tests for all modules
python tests/run_tests.py

# Verify lab concepts implementation
python tests/test_lab_concepts.py
```

### Test Coverage

- Authentication module
- Blockchain functionality
- Classical ciphers (Caesar, Vigenère)
- Modern ciphers (XOR, Block)
- Hashing and HMAC
- Crypto math primitives
- Storage encryption/decryption
- Lab concepts verification

---

## Documentation

### Quick Links
- [Quick Start Guide](docs/guides/QUICKSTART.md)
- [Network Setup](docs/guides/NETWORK_GUIDE.md)
- [Storage Security](docs/guides/STORAGE_LAB_CONCEPTS.md)
- [Lab Mapping](docs/api/LAB_MAPPING.md)
- [Architecture](docs/api/ARCHITECTURE.md)
- [Documentation Hub](docs/INDEX.md)

### Key Documents
- **For Students**: Start with [QUICKSTART.md](docs/guides/QUICKSTART.md)
- **For Security Details**: Read [STORAGE_LAB_CONCEPTS.md](docs/guides/STORAGE_LAB_CONCEPTS.md)
- **For Lab Concepts**: See [LAB_MAPPING.md](docs/api/LAB_MAPPING.md)
- **For Implementation**: Check [LAB_CONCEPTS_IMPLEMENTATION.md](docs/LAB_CONCEPTS_IMPLEMENTATION.md)
- **For Advanced Labs**:
  - [LAB12.md](docs/guides/LAB12.md) - Diffie-Hellman Key Exchange
  - [LAB13.md](docs/guides/LAB13.md) - AEAD (Authenticated Encryption)
  - [LAB14.md](docs/guides/LAB14.md) - Key Management
  - [LAB15.md](docs/guides/LAB15.md) - Post-Quantum & Forward Secrecy

---

## Educational Objectives

### What Students Learn

1. **Applied Cryptography**: Real-world use of classical and modern ciphers
2. **Security Principles**: Confidentiality, integrity, authentication
3. **Blockchain Technology**: Practical implementation of distributed ledger
4. **Network Security**: Secure client-server communication
5. **Key Management**: KDC and public key distribution
6. **Data Protection**: Encryption at rest with integrity verification
7. **Integration**: How multiple security concepts work together
8. **Advanced Cryptography**: DH key exchange, AEAD, forward secrecy, post-quantum readiness

### Lab Concepts Demonstrated

- **Lab 01-02**: Python fundamentals applied throughout
- **Lab 03-04**: Classical ciphers in messaging context
- **Lab 05**: Modern ciphers protecting stored data
- **Lab 06**: Hashing and HMAC ensuring integrity
- **Lab 07**: Blockchain providing audit trail
- **Lab 09**: ElGamal enabling secure communication
- **Lab 11**: KDC managing public keys
- **Lab 12**: Diffie-Hellman key exchange for session establishment
- **Lab 13**: AEAD combining encryption and authentication
- **Lab 14**: Key lifecycle management (rotation, revocation)
- **Lab 15**: Forward secrecy and post-quantum cryptography readiness

---

## Technical Details

### Security Implementation

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| Storage Encryption | XOR Stream Cipher (Lab 05) | 128-bit | Data at rest |
| Key Derivation | SHA-256 (Lab 06) | 256-bit → 128-bit | Master key → encryption key |
| Integrity Check | HMAC-SHA256 (Lab 06) | 256-bit | Tamper detection |
| File Hashing | SHA-256 (Lab 06) | 256-bit | Additional verification |
| Password Hashing | SHA-256 (Lab 06) | 256-bit | User authentication |
| ElGamal Keys | Prime-based (Lab 09) | 16-bit (demo) | Public key crypto |
| Blockchain PoW | SHA-256 (Lab 07) | Variable difficulty | Mining |

### Performance Characteristics

- **Encryption Speed**: XOR is fast (simple operations)
- **Storage Format**: JSON (human-readable, debuggable)
- **Network Protocol**: TCP/IP (reliable delivery)
- **Blockchain Mining**: Configurable difficulty (demo: 2 zeros)

### Security Considerations

**Educational Purpose**: This project uses simplified cryptography for learning:
- XOR cipher is educational, not production-grade
- 16-bit ElGamal keys are for demo (real-world uses 2048+ bits)
- Simplified Proof of Work (production uses higher difficulty)

**Lab Concepts Applied Correctly**: All implementations follow lab specifications

---

## Contributing

Contributions are welcome! This is an educational project, so focus on:
- Improving documentation
- Adding more lab concept demonstrations
- Enhancing test coverage
- Bug fixes

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Computer Security Labs 01-15**: Foundation for all concepts
- **Educational Purpose**: Designed for learning and demonstration
- **Open Source**: Built with Python standard library

---

## Author & Dedication

**Author**: Sabghat Ullah Qureshi

**Dedicated to**: BCS4A & BCS4B Students, COMSATS University Islamabad (CUI)

This project is created as an educational resource for Computer Science students, demonstrating practical implementations of cryptographic concepts covered in Labs 01-11.

---

## Contact & Support

- **Repository**: [https://github.com/sabghat90/SMS](https://github.com/sabghat90/SMS)
- **Issues**: [GitHub Issues](https://github.com/sabghat90/SMS/issues)
- **Documentation**: See `docs/` folder

---

## Quick Reference

### Commands Cheat Sheet

```bash
# Installation (no packages needed!)
git clone https://github.com/sabghat90/SMS.git
cd SMS

# Run standalone
python main.py

# Run server + client (NEW - SIMPLIFIED!)
python server.py    # Terminal 1
python client.py    # Terminal 2

# Test lab concepts
python tests/test_lab_concepts.py

# Test Labs 12-15
python tests/test_lab12.py
python tests/test_lab13.py
python tests/test_lab14.py
python tests/test_lab15.py

# Run all tests
python tests/run_tests.py

# Run lab demos
python examples/demo_lab12.py  # Diffie-Hellman
python examples/demo_lab13.py  # AEAD
python examples/demo_lab14.py  # Key Management
python examples/demo_lab15.py  # Post-Quantum & Forward Secrecy
```

### Features at a Glance

- **9 Encryption Methods**: Caesar, Vigenère, XOR, Block, ElGamal, DH Key Exchange, AEAD
- **Key Management**: Full lifecycle (creation, rotation, revocation)
- **Forward Secrecy**: Ephemeral session keys
- **Post-Quantum Ready**: Educational PQ primitives
- **Blockchain**: Proof of Work message ledger
- **Secure Storage**: XOR + HMAC encrypted files
- **Multi-User**: Network server with KDC
- **100% Tested**: Comprehensive test suite
- **Well Documented**: Complete guides and API reference
- **Pure Lab Concepts**: No external crypto libraries

---

<div align="center">

**Built for Computer Security Education**

**100% Lab Concepts (01-15)** | **Production Ready for Learning** | **Educational Excellence**

</div>
