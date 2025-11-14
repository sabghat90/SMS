# Lab 05 - Modern Ciphers (XOR Stream Cipher and Block Cipher)

## Overview

Lab 05 introduces modern cryptographic primitives that form the basis of secure communication systems. Unlike classical ciphers, these methods operate on binary data and provide stronger security guarantees.

**Module**: `src/core/modern_ciphers.py`

## Part A: XOR Stream Cipher

### Concept

The XOR (exclusive OR) stream cipher is a fundamental building block of modern cryptography. It encrypts data by combining plaintext with a keystream using the XOR operation.

### How It Works

1. Generate a keystream (same length as plaintext)
2. XOR each byte of plaintext with corresponding keystream byte
3. Result is ciphertext

**XOR Properties**:
- A XOR B XOR B = A (self-inverse)
- Makes encryption and decryption identical operations
- If keystream is truly random, cipher is theoretically unbreakable (One-Time Pad)

### Mathematical Foundation

```
Encryption: C = P XOR K
Decryption: P = C XOR K

Where:
- P = Plaintext byte
- K = Key byte
- C = Ciphertext byte
```

### API Reference

```python
class XORStreamCipher:
    def __init__(self, key=None)
    
    @staticmethod
    def generate_key(length=16) -> str
    
    def encrypt(self, plaintext, key=None) -> str
    
    def decrypt(self, ciphertext, key=None) -> str
```

### Usage Example

```python
from src.core.modern_ciphers import XORStreamCipher

# Generate a random key
key = XORStreamCipher.generate_key(length=32)
print(f"Key: {key}")

# Create cipher instance
cipher = XORStreamCipher()

# Encrypt message
plaintext = "Secret message"
ciphertext = cipher.encrypt(plaintext, key)
print(f"Encrypted: {ciphertext}")

# Decrypt message
decrypted = cipher.decrypt(ciphertext, key)
print(f"Decrypted: {decrypted}")
assert decrypted == plaintext
```

### Security Considerations

**Strengths**:
- Very fast (XOR is efficient)
- Simple to implement
- Provably secure if keystream is truly random and never reused

**Critical Requirements**:
1. **Key must be random**: Predictable keys break security
2. **Key must never be reused**: Reusing a key allows ciphertext-only attacks
3. **Key must be as long as plaintext**: For One-Time Pad security

**Weaknesses**:
- Malleable: Flipping a bit in ciphertext flips corresponding plaintext bit
- No authentication: Cannot detect tampering
- Key reuse is catastrophic

### Key Reuse Attack Example

```python
# DANGEROUS: Never do this!
key = "shared_key"
cipher = XORStreamCipher(key=key.encode())

# Two messages encrypted with same key
msg1 = "attack at dawn"
msg2 = "retreat at dusk"

c1 = cipher.encrypt(msg1)
c2 = cipher.encrypt(msg2)

# Attacker can XOR ciphertexts: C1 XOR C2 = P1 XOR P2
# This reveals information about both plaintexts!
```

## Part B: Mini Block Cipher

### Concept

A block cipher encrypts fixed-size blocks of data using a key and multiple rounds of transformations. This implementation demonstrates the core principles of block ciphers like AES.

**Module**: `src/core/modern_ciphers.py` - `MiniBlockCipher` class

### How It Works

1. **Block Processing**: Data divided into fixed-size blocks (8 bytes)
2. **Rounds**: Multiple transformation rounds for security
3. **Operations per Round**:
   - **Substitution**: Replace bytes using S-box
   - **Permutation**: Rearrange byte positions
   - **Key Mixing**: XOR with round key

### API Reference

```python
class MiniBlockCipher:
    BLOCK_SIZE = 8  # 8-byte blocks
    
    def __init__(self, key: bytes, rounds: int = 4)
    
    def encrypt(self, plaintext: str) -> str
    
    def decrypt(self, ciphertext_hex: str) -> str
```

### Usage Example

```python
from src.core.modern_ciphers import MiniBlockCipher

# Create cipher with 32-byte key
key = b'this_is_a_32_byte_secret_key!!!!'
cipher = MiniBlockCipher(key, rounds=4)

# Encrypt message (automatically pads to block size)
plaintext = "Hello, this is a secret message!"
ciphertext = cipher.encrypt(plaintext)
print(f"Encrypted: {ciphertext}")

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted}")
assert decrypted == plaintext
```

### Block Cipher Modes

This implementation uses **ECB mode** (Electronic Codebook) for simplicity. In production systems, use modes like CBC, CTR, or GCM.

**ECB Weaknesses**:
- Identical plaintext blocks produce identical ciphertext blocks
- Reveals patterns in data
- Not recommended for production use

## Comparison: Stream vs Block Ciphers

| Feature | Stream Cipher | Block Cipher |
|---------|--------------|--------------|
| **Data Unit** | Bit/byte at a time | Fixed-size blocks |
| **Speed** | Very fast | Moderate |
| **Padding** | Not needed | Required |
| **Memory** | Low | Higher (block buffering) |
| **Parallelization** | Difficult | Possible (in some modes) |
| **Examples** | RC4, ChaCha20 | AES, DES, Blowfish |

## Real-World Applications

### Stream Ciphers Used In:
- SSL/TLS (ChaCha20-Poly1305)
- Mobile communications (A5/1, A5/3)
- Wireless networks (RC4 in WEP - now deprecated)

### Block Ciphers Used In:
- SSL/TLS (AES-GCM)
- Disk encryption (AES in XTS mode)
- File encryption (AES in CBC/CTR mode)
- VPNs (AES in various modes)

## Testing Both Ciphers

```python
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher

def test_stream_cipher():
    """Test XOR stream cipher"""
    cipher = XORStreamCipher()
    key = XORStreamCipher.generate_key(32)
    
    plaintext = "Test message 123"
    ciphertext = cipher.encrypt(plaintext, key)
    decrypted = cipher.decrypt(ciphertext, key)
    
    assert decrypted == plaintext
    print("Stream cipher test passed")

def test_block_cipher():
    """Test mini block cipher"""
    key = b'32_byte_key_for_block_cipher!!!'
    cipher = MiniBlockCipher(key, rounds=4)
    
    plaintext = "Block cipher test"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    
    assert decrypted == plaintext
    print("Block cipher test passed")

# Run tests
test_stream_cipher()
test_block_cipher()
```

## Integration with SMS Project

Both ciphers are used in the Secure Messaging System:

1. **XOR Stream Cipher**: Used for encrypting stored data (see `src/core/storage.py`)
2. **Message Encryption**: Used in standalone mode for basic encryption
3. **AEAD Construction**: XOR cipher combined with HMAC in Lab 13

## Security Best Practices

1. **Always use authenticated encryption** (combine with HMAC - see Lab 06)
2. **Never reuse keys or nonces**
3. **Use cryptographically secure random number generators**
4. **In production, use standard libraries** (cryptography, PyCryptodome)
5. **These implementations are educational** - use battle-tested implementations for real systems

## Further Reading

- "Understanding Cryptography" by Christof Paar (Chapter 2 - Stream Ciphers, Chapter 3 - Block Ciphers)
- "Applied Cryptography" by Bruce Schneier (Chapter 9)
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
- Study AES (Advanced Encryption Standard) for real-world block cipher
- Study ChaCha20 for modern stream cipher design

## Common Pitfalls

1. **Key Reuse in Stream Ciphers**: Always use unique nonces/IVs
2. **ECB Mode**: Never use ECB for production (use CBC, CTR, or GCM)
3. **No Authentication**: Always authenticate ciphertext (encrypt-then-MAC or use AEAD)
4. **Weak Keys**: Use cryptographically secure random key generation
5. **Rolling Your Own Crypto**: Use standard implementations in production
