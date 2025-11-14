# Lab 06 - Hashing and Message Integrity

## Overview

Lab 06 introduces cryptographic hash functions and message authentication codes (MACs), which are essential for ensuring data integrity and authenticity in secure systems.

**Module**: `src/core/hashing.py`

## Part A: SHA-256 Hashing

### Concept

A **cryptographic hash function** takes input of arbitrary length and produces a fixed-size output (digest) with the following properties:

1. **Deterministic**: Same input always produces same output
2. **Fast to compute**: Efficient calculation
3. **Pre-image resistance**: Given hash H, infeasible to find input M where hash(M) = H
4. **Second pre-image resistance**: Given M1, infeasible to find M2 where hash(M1) = hash(M2)
5. **Collision resistance**: Infeasible to find any M1, M2 where hash(M1) = hash(M2)
6. **Avalanche effect**: Small input change drastically changes output

### SHA-256 Specifications

- **Output Size**: 256 bits (32 bytes, 64 hex characters)
- **Block Size**: 512 bits
- **Security**: No known practical attacks
- **Standard**: FIPS 180-4

### API Reference

```python
class MessageIntegrity:
    @staticmethod
    def compute_hash(message) -> str
    
    @staticmethod
    def hash_message(message) -> str  # Alias
    
    @staticmethod
    def verify_hash(message, expected_hash) -> tuple[bool, str]
    
    @staticmethod
    def verify_message(message, expected_hash) -> bool  # Alias
```

### Usage Example

```python
from src.core.hashing import MessageIntegrity

# Compute hash
message = "Hello, World!"
hash_value = MessageIntegrity.compute_hash(message)
print(f"SHA-256 Hash: {hash_value}")
# Output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f

# Verify integrity
is_valid, computed = MessageIntegrity.verify_hash(message, hash_value)
print(f"Valid: {is_valid}")  # True

# Tampering detection
tampered = "Hello, World?"
is_valid = MessageIntegrity.verify_message(tampered, hash_value)
print(f"Valid: {is_valid}")  # False
```

### Avalanche Effect Demonstration

```python
from src.core.hashing import MessageIntegrity

# Small change in input
msg1 = "Hello, World!"
msg2 = "Hello, World?"  # One character changed

hash1 = MessageIntegrity.compute_hash(msg1)
hash2 = MessageIntegrity.compute_hash(msg2)

print(f"Hash1: {hash1}")
print(f"Hash2: {hash2}")
print(f"Different: {hash1 != hash2}")

# Hashes are completely different despite minimal input change
```

## Part B: HMAC (Hash-based Message Authentication Code)

### Concept

**HMAC** combines a hash function with a secret key to provide both integrity and authenticity. It answers two questions:
1. Has the message been tampered with? (Integrity)
2. Did it come from someone who knows the secret key? (Authenticity)

### How It Works

```
HMAC(key, message) = H((key XOR opad) || H((key XOR ipad) || message))

Where:
- H = hash function (SHA-256)
- opad = outer padding (0x5c repeated)
- ipad = inner padding (0x36 repeated)
- || = concatenation
```

### API Reference

```python
class MessageIntegrity:
    @staticmethod
    def compute_hmac(message, key) -> str
    
    @staticmethod
    def verify_hmac(message, key, expected_hmac) -> bool
    
    @staticmethod
    def verify_hmac_constant_time(message, key, expected_hmac) -> bool
```

### Usage Example

```python
from src.core.hashing import MessageIntegrity
import secrets

# Generate a secret key
key = secrets.token_bytes(32)

# Create HMAC signature
message = "Transfer $100 to Alice"
signature = MessageIntegrity.compute_hmac(message, key)
print(f"HMAC Signature: {signature}")

# Verify message authenticity
is_valid = MessageIntegrity.verify_hmac(message, key, signature)
print(f"Valid: {is_valid}")  # True

# Detect tampering
tampered = "Transfer $999 to Alice"
is_valid = MessageIntegrity.verify_hmac(tampered, key, signature)
print(f"Valid: {is_valid}")  # False
```

### Timing Attack Protection

```python
# Use constant-time comparison to prevent timing attacks
is_valid = MessageIntegrity.verify_hmac_constant_time(message, key, signature)

# Regular comparison leaks information through timing
# Constant-time comparison prevents this side-channel attack
```

## Hash vs HMAC Comparison

| Feature | Hash (SHA-256) | HMAC |
|---------|---------------|------|
| **Purpose** | Integrity only | Integrity + Authenticity |
| **Key Required** | No | Yes |
| **Tampering Detection** | Yes | Yes |
| **Sender Authentication** | No | Yes |
| **Collision Resistance** | Critical | Important |
| **Example Use** | File checksums | API signatures |

## Real-World Applications

### SHA-256 Used For:
- **File Integrity**: Verify downloads (checksums)
- **Password Storage**: Hash passwords before storing (with salt)
- **Blockchain**: Bitcoin uses SHA-256 for proof-of-work
- **Digital Signatures**: Part of RSA/ECDSA signature schemes
- **Content Addressing**: IPFS, Git use hashes as identifiers

### HMAC Used For:
- **API Authentication**: AWS, Azure API signatures
- **Session Cookies**: Signed session tokens
- **Webhooks**: Verify webhook authenticity (GitHub, Stripe)
- **Message Authentication**: TLS, IPsec use HMAC
- **JWT Tokens**: HMAC-based JSON Web Tokens

## Implementation in SMS Project

### Storage Integrity
```python
# From src/core/storage.py

# Hash files for integrity checking
file_hash = MessageIntegrity.compute_hash(file_content)
self._save_integrity_hash(file_hash)

# Verify file hasn't been tampered with
is_valid = self.verify_file_integrity()
```

### Authenticated Encryption (Lab 13)
```python
# HMAC used in AEAD construction
# Encrypt data
ciphertext = cipher.encrypt(plaintext)

# Create authentication tag
tag = MessageIntegrity.compute_hmac(
    ciphertext + aad,  # Authenticate ciphertext and metadata
    key
)

# Return ciphertext and tag
return ciphertext, tag
```

## Security Best Practices

1. **Hash Functions**:
   - Use SHA-256 or SHA-3 (avoid SHA-1, MD5)
   - Don't use for passwords directly (use bcrypt, Argon2, or PBKDF2)
   - Store file hashes separately from files

2. **HMAC**:
   - Use keys at least 32 bytes (256 bits)
   - Never reuse keys across different contexts
   - Always use constant-time comparison
   - Don't use hash(key + message) - vulnerable to length extension

3. **Key Management**:
   - Generate keys using cryptographically secure RNG
   - Store keys securely (not in code!)
   - Rotate keys periodically

## Testing

```python
from src.core.hashing import MessageIntegrity
import secrets

def test_hashing():
    """Test SHA-256 hashing"""
    message = "Test message"
    
    # Compute hash
    hash1 = MessageIntegrity.compute_hash(message)
    hash2 = MessageIntegrity.compute_hash(message)
    
    # Same input produces same hash
    assert hash1 == hash2
    
    # Verify hash
    is_valid, computed = MessageIntegrity.verify_hash(message, hash1)
    assert is_valid
    assert computed == hash1
    
    print("Hashing tests passed")

def test_hmac():
    """Test HMAC authentication"""
    key = secrets.token_bytes(32)
    message = "Authenticate this message"
    
    # Create HMAC
    signature = MessageIntegrity.compute_hmac(message, key)
    
    # Verify HMAC
    assert MessageIntegrity.verify_hmac(message, key, signature)
    
    # Tampering detection
    tampered = message + "X"
    assert not MessageIntegrity.verify_hmac(tampered, key, signature)
    
    # Wrong key detection
    wrong_key = secrets.token_bytes(32)
    assert not MessageIntegrity.verify_hmac(message, wrong_key, signature)
    
    print("HMAC tests passed")

# Run tests
test_hashing()
test_hmac()
```

## Common Pitfalls

1. **Using MD5 or SHA-1**: Both are broken - use SHA-256 or SHA-3
2. **Hash(key + message)**: Vulnerable to length extension attacks - use HMAC
3. **Timing Attacks**: Use constant-time comparison for HMAC verification
4. **Storing Passwords as Hashes**: Use password-specific functions (bcrypt, Argon2)
5. **Not Salting Hashes**: For password storage, always use unique salts

## Advanced Topics

### Password Hashing
```python
# Don't do this for passwords!
password_hash = MessageIntegrity.compute_hash(password)  # Vulnerable to rainbow tables

# Instead, use proper password hashing (not in this lab)
# - bcrypt
# - Argon2id
# - PBKDF2
# These include salting, iteration, and memory hardness
```

### Hash Chains (Used in Blockchain - Lab 07)
```python
# Each block's hash includes previous block's hash
block1_hash = hash(block1_data)
block2_hash = hash(block2_data + block1_hash)
block3_hash = hash(block3_data + block2_hash)

# Creates immutable chain - changing block1 invalidates all subsequent blocks
```

## Further Reading

- NIST FIPS 180-4: Secure Hash Standard (SHS)
- NIST FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- "Cryptography Engineering" by Ferguson, Schneier, Kohno (Chapter 6)
- Study PBKDF2, bcrypt, and Argon2 for password hashing
- Learn about Merkle trees and their use in blockchain
