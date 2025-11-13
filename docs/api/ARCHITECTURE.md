# System Architecture Documentation
## Secure Messaging System (SMS)

---

## System Architecture

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURE MESSAGING SYSTEM                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   USER INTERFACE LAYER                    │  │
│  │                      (main.py)                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              APPLICATION LOGIC LAYER                      │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │  │
│  │  │Authentication│  │   Encryption  │  │   Blockchain   │  │  │
│  │  │   Module     │  │    Engine     │  │    Manager     │  │  │
│  │  └─────────────┘  └──────────────┘  └────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              CRYPTOGRAPHIC LAYER                          │  │
│  ├──────────────────────────────────────────────────────────┤  │
│  │  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐  │  │
│  │  │Classical│  │  Modern  │  │Hashing │  │  ElGamal  │  │  │
│  │  │ Ciphers │  │ Ciphers  │  │        │  │    KDC    │  │  │
│  │  └─────────┘  └──────────┘  └────────┘  └───────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                            ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           CRYPTOGRAPHIC MATH PRIMITIVES                   │  │
│  │  (GCD, Modular Inverse, Prime Gen, Power Mod)            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Architecture

### Message Sending Workflow

```
┌──────────┐
│  SENDER  │
└────┬─────┘
     │
     │ 1. Login (Authentication)
     ▼
┌─────────────────┐
│ Authentication  │──────► Verify credentials
│     Module      │        Create session
└────┬────────────┘
     │
     │ 2. Compose Message
     ▼
┌─────────────────┐
│   Plaintext     │──────► "Hello Bob!"
│    Message      │
└────┬────────────┘
     │
     │ 3. Compute Hash
     ▼
┌─────────────────┐
│  Hash Module    │──────► SHA-256(plaintext)
└────┬────────────┘        = message_hash
     │
     │ 4. Select Encryption Method
     ▼
┌─────────────────────────────────────┐
│      Encryption Engine              │
├─────────────────────────────────────┤
│  Choose:                            │
│  • Caesar Cipher                    │
│  • Vigenère Cipher                  │
│  • XOR Stream Cipher                │
│  • Mini Block Cipher                │
└────┬────────────────────────────────┘
     │
     │ 5. Encrypt
     ▼
┌─────────────────┐
│   Ciphertext    │──────► Encrypted message
└────┬────────────┘
     │
     │ 6. Create Block
     ▼
┌─────────────────────────────────────┐
│         Blockchain                  │
├─────────────────────────────────────┤
│  Block Data:                        │
│  • Sender                           │
│  • Receiver                         │
│  • Ciphertext                       │
│  • Message Hash                     │
│  • Timestamp                        │
│  • Previous Hash                    │
├─────────────────────────────────────┤
│  Mine Block (Proof of Work)         │
└────┬────────────────────────────────┘
     │
     │ 7. Add to Chain
     ▼
┌─────────────────┐
│  Immutable      │──────► Message stored
│  Blockchain     │        permanently
└─────────────────┘
```

### Message Receiving Workflow

```
┌──────────┐
│ RECEIVER │
└────┬─────┘
     │
     │ 1. Login
     ▼
┌─────────────────┐
│ Authentication  │
└────┬────────────┘
     │
     │ 2. View Messages
     ▼
┌─────────────────┐
│   Blockchain    │──────► Retrieve blocks
│     Query       │        for receiver
└────┬────────────┘
     │
     │ 3. Select Message
     ▼
┌─────────────────┐
│   Ciphertext    │
│   from Block    │
└────┬────────────┘
     │
     │ 4. Decrypt (with key)
     ▼
┌─────────────────┐
│  Decryption     │──────► Using same cipher
│    Engine       │        and key
└────┬────────────┘
     │
     │ 5. Get Plaintext
     ▼
┌─────────────────┐
│   Plaintext     │
│    Message      │
└────┬────────────┘
     │
     │ 6. Verify Integrity
     ▼
┌─────────────────────────────────────┐
│       Hash Verification             │
├─────────────────────────────────────┤
│  Compute: SHA-256(decrypted_msg)    │
│  Compare: computed_hash == stored   │
│  Result: Valid / Tampered      │
└─────────────────────────────────────┘
```

---

## Module Dependencies

```
main.py
    ├── authentication.py
    │   └── hashlib (stdlib)
    │
    ├── classical_ciphers.py
    │   └── (no dependencies)
    │
    ├── modern_ciphers.py
    │   └── os (stdlib)
    │
    ├── hashing.py
    │   ├── hashlib (stdlib)
    │   └── hmac (stdlib)
    │
    ├── blockchain.py
    │   ├── hashlib (stdlib)
    │   ├── json (stdlib)
    │   └── datetime (stdlib)
    │
    └── elgamal.py
        └── crypto_math.py
            └── random (stdlib)
```

---

## Security Architecture

### Security Layers

```
┌────────────────────────────────────────────┐
│         APPLICATION SECURITY               │
├────────────────────────────────────────────┤
│  • User Authentication                     │
│  • Session Management                      │
│  • Access Control                          │
└────────────────────────────────────────────┘
                    ▼
┌────────────────────────────────────────────┐
│      CRYPTOGRAPHIC SECURITY                │
├────────────────────────────────────────────┤
│  • Message Encryption (Confidentiality)    │
│  • Hash Verification (Integrity)           │
│  • Key Management (ElGamal + KDC)          │
└────────────────────────────────────────────┘
                    ▼
┌────────────────────────────────────────────┐
│         DATA SECURITY                      │
├────────────────────────────────────────────┤
│  • Blockchain Immutability                 │
│  • Non-repudiation                         │
│  • Audit Trail                             │
└────────────────────────────────────────────┘
```

### Cryptographic Operations

```
SYMMETRIC ENCRYPTION OPERATIONS
================================
Classical Ciphers:
  Caesar:    plaintext ──[shift]──> ciphertext
  Vigenère:  plaintext ──[keyword]──> ciphertext

Modern Ciphers:
  XOR:       plaintext ⊕ keystream = ciphertext
  Block:     plaintext ──[S-box,P-box,⊕]──> ciphertext


ASYMMETRIC ENCRYPTION OPERATIONS
=================================
ElGamal Key Generation:
  1. Choose prime p, generator g
  2. Private key: x (random)
  3. Public key: y = g^x mod p

ElGamal Encryption:
  1. Choose random k
  2. c1 = g^k mod p
  3. c2 = m * y^k mod p

ElGamal Decryption:
  1. s = c1^x mod p
  2. m = c2 * s^(-1) mod p


HASHING OPERATIONS
==================
Message Integrity:
  hash = SHA-256(plaintext)
  verify: SHA-256(decrypted) == hash

HMAC:
  HMAC-SHA256(message, key)
```

---

## Data Structures

### User Storage
```python
users = {
    'alice': {
        'password_hash': 'a9b8c7...',
        'created_at': '2025-10-31 14:23:45',
        'email': 'alice@example.com',
        'login_count': 5
    }
}
```

### Session Storage
```python
active_sessions = {
    'session_abc123': {
        'username': 'alice',
        'login_time': '2025-10-31 14:30:00'
    }
}
```

### Key Distribution Center
```python
public_keys = {
    'alice': ElGamalKeyPair(
        p=65537,
        g=3,
        private_key=None,  # Not stored in KDC
        public_key=54321
    )
}
```

### Blockchain Structure
```python
blockchain = [
    Block(
        index=0,
        timestamp='2025-10-31 14:00:00',
        data={'message': 'Genesis Block'},
        previous_hash='0',
        hash='00a1b2c3...',
        nonce=1234
    ),
    Block(
        index=1,
        timestamp='2025-10-31 14:05:00',
        data={
            'sender': 'alice',
            'receiver': 'bob',
            'ciphertext': '8f3e2a...',
            'message_hash': '9b871c...',
            'encryption_method': 'Vigenère Cipher'
        },
        previous_hash='00a1b2c3...',
        hash='00d4e5f6...',
        nonce=5678
    )
]
```

---

## Component Responsibilities

### Authentication Module
- **Input:** Username, password
- **Output:** Session ID
- **Responsibilities:**
  - Validate credentials
  - Hash passwords
  - Manage sessions
  - Track login history

### Classical Ciphers Module
- **Input:** Plaintext, key
- **Output:** Ciphertext
- **Responsibilities:**
  - Caesar cipher encryption/decryption
  - Vigenère cipher encryption/decryption
  - Character substitution

### Modern Ciphers Module
- **Input:** Plaintext, key
- **Output:** Ciphertext (hex)
- **Responsibilities:**
  - XOR stream cipher
  - Mini block cipher (SPN)
  - Key generation
  - Padding/unpadding

### Hashing Module
- **Input:** Message
- **Output:** Hash (SHA-256)
- **Responsibilities:**
  - Compute message digests
  - Verify message integrity
  - HMAC generation
  - Multi-algorithm hashing

### Blockchain Module
- **Input:** Transaction data
- **Output:** Block, chain
- **Responsibilities:**
  - Create blocks
  - Mine blocks (PoW)
  - Validate chain
  - Query blocks

### ElGamal & KDC Module
- **Input:** Message, public key
- **Output:** Ciphertext pair
- **Responsibilities:**
  - Generate key pairs
  - Encrypt/decrypt messages
  - Register public keys
  - Distribute keys

### Crypto Math Module
- **Input:** Numbers, operations
- **Output:** Computed results
- **Responsibilities:**
  - Modular arithmetic
  - Prime generation
  - GCD, modular inverse
  - Power modulo

---

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Caesar Cipher | O(n) | n = message length |
| Vigenère Cipher | O(n) | n = message length |
| XOR Stream | O(n) | n = message length |
| Block Cipher | O(n) | n = message length |
| SHA-256 Hash | O(n) | n = message length |
| ElGamal Encrypt | O(log e) | e = exponent size |
| ElGamal Decrypt | O(log x) | x = private key |
| Prime Generation | O(k·log³ n) | k = rounds, n = bits |
| Block Mining | O(2^d) | d = difficulty |
| Chain Validation | O(m) | m = number of blocks |

### Space Complexity

| Component | Space | Notes |
|-----------|-------|-------|
| User Storage | O(u) | u = number of users |
| Blockchain | O(b) | b = number of blocks |
| KDC | O(u) | u = registered users |
| Session Storage | O(s) | s = active sessions |

---

## Error Handling Strategy

```
Input Validation
    ├── Username/Password validation
    ├── Cipher key validation
    ├── Recipient existence check
    └── Message length check
         │
         ▼
Encryption Errors
    ├── Message too large for ElGamal
    ├── Invalid key format
    └── Encoding errors
         │
         ▼
Decryption Errors
    ├── Wrong key provided
    ├── Corrupted ciphertext
    └── Hash mismatch
         │
         ▼
Blockchain Errors
    ├── Invalid block hash
    ├── Broken chain link
    └── Mining failure
         │
         ▼
User Notification
    └── Clear error messages
```

---

## Extensibility Points

### Adding New Cipher
1. Create cipher class in appropriate module
2. Implement `encrypt()` and `decrypt()` methods
3. Add to `select_encryption_method()` in main.py
4. Update documentation

### Adding Database Support
1. Replace dictionaries with database queries
2. Implement persistence layer
3. Add migration scripts
4. Update authentication module

### Adding Network Support
1. Implement socket-based communication
2. Create client-server architecture
3. Add message serialization
4. Implement protocol handlers

---

**Document Version:** 1.2  
**Last Updated:** Nov 10, 2025
