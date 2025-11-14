# Lab 13 - AEAD (Authenticated Encryption with Associated Data)

## Overview

Lab 13 demonstrates **AEAD (Authenticated Encryption with Associated Data)**, a modern cryptographic construction that provides both confidentiality and integrity in a single operation.

**Module**: `src/core/aead.py`

## Concepts Demonstrated

### 1. Authenticated Encryption
Traditional approach: Encrypt then MAC (two separate operations)
AEAD approach: Single operation providing both

Benefits:
- Simpler API (less error-prone)
- Better performance (optimized internally)
- Stronger security guarantees

### 2. Additional Authenticated Data (AAD)
- Metadata that must be authenticated but not encrypted
- Examples: message headers, protocol version, sender ID
- Tampering with AAD is detected just like tampering with ciphertext

### 3. Tampering Detection
- Any modification to ciphertext or AAD causes decryption to fail
- Uses constant-time comparison to prevent timing attacks
- Provides integrity and authenticity guarantees

### 4. Educational Implementation
This module combines:
- **Lab 05 concepts**: XOR stream cipher for encryption
- **Lab 06 concepts**: HMAC-SHA256 for authentication
- Modern AEAD design patterns

Real AEAD modes: AES-GCM, ChaCha20-Poly1305

## API Reference

### Functions

```python
encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> Tuple[bytes, bytes]
```
Encrypt plaintext and authenticate with AAD.

**Args:**
- `key`: 32-byte encryption key
- `nonce`: Unique nonce (must NEVER repeat with same key!)
- `aad`: Additional data to authenticate (not encrypted)
- `plaintext`: Data to encrypt

**Returns:**
- `(ciphertext, authentication_tag)`

```python
decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes
```
Verify authentication and decrypt.

**Args:**
- `key`: 32-byte encryption key
- `nonce`: Nonce used during encryption
- `aad`: Additional authenticated data
- `ciphertext`: Encrypted data
- `tag`: Authentication tag from encrypt()

**Returns:**
- Decrypted plaintext

**Raises:**
- `ValueError`: If authentication fails (tampering detected)

## Usage Examples

### Basic Encryption/Decryption

```python
from src.core import lab13_aead as lab13
import secrets

key = secrets.token_bytes(32)
nonce = secrets.token_bytes(16)
aad = b"message-id:12345"
plaintext = b"secret data"

# Encrypt
ciphertext, tag = lab13.encrypt(key, nonce, aad, plaintext)

# Decrypt
decrypted = lab13.decrypt(key, nonce, aad, ciphertext, tag)

assert decrypted == plaintext
```

### Tampering Detection

```python
# Any modification is detected
tampered_ct = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])

try:
    lab13.decrypt(key, nonce, aad, tampered_ct, tag)
    print("ERROR: Should have detected tampering!")
except ValueError as e:
    print(f"Tampering detected: {e}")
```

### AAD Protection

```python
# AAD is authenticated (but not encrypted)
aad = b"sender:alice,receiver:bob"
ct, tag = lab13.encrypt(key, nonce, aad, plaintext)

# Changing AAD causes authentication failure
modified_aad = b"sender:eve,receiver:bob"
try:
    lab13.decrypt(key, nonce, modified_aad, ct, tag)
except ValueError:
    print("AAD modification detected!")
```

## Running the Demo

```bash
# Run comprehensive demo with tampering tests
python examples/demo_lab13.py

# Run unit tests
python tests/test_lab13.py
```

## Real-World Applications

### TLS 1.3
- Uses AES-GCM or ChaCha20-Poly1305 AEAD
- AAD includes: protocol version, sequence number, record type

### Signal Protocol
- Uses AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
- Modern variants use AEAD modes

### Disk Encryption
- VeraCrypt, LUKS use authenticated encryption
- Protects against bit-flipping attacks

### Cloud Storage
- AWS S3, Google Cloud use AEAD for client-side encryption
- Prevents tampering with encrypted data

## Security Considerations

### Critical: Nonce Must Be Unique
```python
# NEVER do this:
for msg in messages:
    ct, tag = encrypt(key, same_nonce, aad, msg)  # INSECURE!

# DO this:
for msg in messages:
    nonce = secrets.token_bytes(16)  # Fresh nonce each time
    ct, tag = encrypt(key, nonce, aad, msg)  # SECURE
```

### Key Management
- Keys should be rotated periodically
- Use Lab 14 KeyManager for proper lifecycle management

### Constant-Time Operations
- Uses `hmac.compare_digest()` to prevent timing attacks
- Never use `==` to compare authentication tags

## Integration with SMS Project

Lab 13 AEAD can enhance the project's storage layer:

### Current Storage (Lab 05 + Lab 06)
```python
# storage.py uses separate encryption and HMAC
encrypted = xor_encrypt(data)
hmac_tag = compute_hmac(encrypted)
```

### Enhanced with Lab 13
```python
# Single AEAD operation
from src.core import lab13_aead
ciphertext, tag = lab13_aead.encrypt(key, nonce, aad, data)
```

See `src/core/storage.py` for integration opportunities.

## Comparison Table

| Feature | Traditional (Encrypt+MAC) | AEAD |
|---------|---------------------------|------|
| Operations | 2 (encrypt, then MAC) | 1 (combined) |
| API Complexity | Higher (easy to misuse) | Lower (harder to misuse) |
| Performance | Slower (two passes) | Faster (optimized) |
| Security | Good (if done correctly) | Excellent (by design) |
| Examples | CBC+HMAC | AES-GCM, ChaCha20-Poly1305 |

## References

- RFC 5116: An Interface and Algorithms for AEAD
- NIST SP 800-38D: GCM Mode
- Rogaway (2002): "Authenticated-encryption with Associated-data"
