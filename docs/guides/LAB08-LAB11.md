# Labs 08-11 - Advanced Cryptographic Concepts

## Lab 08 - Cryptographic Mathematics

### Overview

Lab 08 covers the mathematical foundations underlying modern cryptography, including prime generation, modular arithmetic, and discrete logarithms.

**Module**: `src/core/crypto_math.py`

### Core Mathematical Concepts

#### Prime Numbers
- **Definition**: Integer > 1 with exactly two divisors (1 and itself)
- **Importance**: Foundation of RSA, ElGamal, and many other systems
- **Security**: Large primes make factorization computationally infeasible

#### Modular Arithmetic
- **Modulo Operation**: `a mod n` = remainder when a is divided by n
- **Properties**: `(a + b) mod n = ((a mod n) + (b mod n)) mod n`
- **Applications**: All public-key cryptography uses modular arithmetic

#### Discrete Logarithm Problem
- **Problem**: Given g, p, and y = g^x mod p, find x
- **Difficulty**: No efficient algorithm known for large primes
- **Security Basis**: ElGamal, Diffie-Hellman key exchange

### API Reference

```python
# Prime number operations
def generate_prime(bits: int) -> int
def is_prime(n: int, k: int = 5) -> bool
def miller_rabin_test(n: int, k: int = 5) -> bool

# Modular arithmetic
def power_mod(base: int, exponent: int, modulus: int) -> int
def extended_gcd(a: int, b: int) -> tuple[int, int, int]
def mod_inverse(a: int, m: int) -> int

# Primitive roots and generators
def find_primitive_root(p: int) -> int
def euler_totient(n: int) -> int

# Random number generation
def secure_random_int(min_val: int, max_val: int) -> int
```

### Usage Examples

```python
from src.core.crypto_math import *

# Generate 16-bit prime
prime = generate_prime(16)
print(f"Generated prime: {prime}")

# Modular exponentiation
result = power_mod(3, 100, 17)  # 3^100 mod 17
print(f"3^100 mod 17 = {result}")

# Find primitive root
g = find_primitive_root(23)
print(f"Primitive root of 23: {g}")
```

---

## Lab 09 - ElGamal Encryption

### Overview

Lab 09 implements the ElGamal public-key cryptosystem, demonstrating asymmetric encryption based on the discrete logarithm problem.

**Module**: `src/core/elgamal.py`

### ElGamal Algorithm

#### Key Generation
1. Choose large prime p
2. Find generator g (primitive root of p)
3. Choose private key x randomly
4. Compute public key y = g^x mod p
5. Public key: (p, g, y), Private key: x

#### Encryption
To encrypt message m:
1. Choose random k
2. Compute c1 = g^k mod p
3. Compute c2 = m × y^k mod p
4. Ciphertext: (c1, c2)

#### Decryption
To decrypt (c1, c2):
1. Compute s = c1^x mod p
2. Compute s_inv = s^(-1) mod p
3. Compute m = c2 × s_inv mod p

### API Reference

```python
class ElGamalKeyPair:
    def __init__(self, p: int, g: int, private_key: int, public_key: int)

class ElGamal:
    @staticmethod
    def generate_keys(bits: int = 16) -> ElGamalKeyPair
    
    @staticmethod
    def encrypt(plaintext, public_key_pair) -> tuple[int, int]
    
    @staticmethod
    def decrypt(ciphertext: tuple[int, int], private_key: int, p: int) -> int
```

### Usage Example

```python
from src.core.elgamal import ElGamal

# Generate keys
keys = ElGamal.generate_keys(bits=16)
print(f"Public key (p, g, y): ({keys.p}, {keys.g}, {keys.public_key})")
print(f"Private key: {keys.private_key}")

# Encrypt message
message = "Hello"
message_int = int.from_bytes(message.encode(), 'big')
c1, c2 = ElGamal.encrypt(message_int, keys)
print(f"Ciphertext: ({c1}, {c2})")

# Decrypt message
decrypted_int = ElGamal.decrypt((c1, c2), keys.private_key, keys.p)
decrypted = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()
print(f"Decrypted: {decrypted}")
```

---

## Lab 10 - Key Distribution Center (KDC)

### Overview

Lab 10 implements a centralized key distribution system that manages symmetric keys for multiple users, demonstrating key management in distributed systems.

**Module**: `src/core/elgamal.py` - `KeyDistributionCenter` class

### KDC Concept

A **Key Distribution Center** is a trusted third party that:
1. Stores symmetric keys for all users
2. Distributes keys securely when users need to communicate
3. Ensures each user pair has a unique shared key
4. Manages key lifecycle (creation, distribution, revocation)

### How It Works

1. **Registration**: Each user registers with KDC and receives a master key
2. **Key Request**: When Alice wants to talk to Bob, she requests a session key
3. **Key Distribution**: KDC creates a session key and sends it encrypted to both users
4. **Secure Communication**: Alice and Bob use the session key for encryption

### API Reference

```python
class KeyDistributionCenter:
    def __init__(self)
    
    def register_user(self, username: str) -> int  # Returns master key
    
    def request_session_key(self, user1: str, user2: str) -> tuple[int, int, int]
    # Returns: (session_key, encrypted_for_user1, encrypted_for_user2)
    
    def get_user_master_key(self, username: str) -> Optional[int]
    
    def list_users(self) -> list[str]
```

### Usage Example

```python
from src.core.elgamal import KeyDistributionCenter

# Create KDC
kdc = KeyDistributionCenter()

# Register users
alice_key = kdc.register_user("alice")
bob_key = kdc.register_user("bob")

# Alice requests session key for communication with Bob
session_key, enc_for_alice, enc_for_bob = kdc.request_session_key("alice", "bob")

# Users decrypt their respective encrypted session keys
# (In real implementation, users would decrypt using their master keys)
print(f"Session key: {session_key}")
print(f"Encrypted for Alice: {enc_for_alice}")
print(f"Encrypted for Bob: {enc_for_bob}")
```

---

## Lab 11 - Digital Signatures

### Overview

Lab 11 demonstrates digital signatures using ElGamal, providing authentication, non-repudiation, and integrity verification.

**Module**: `src/core/elgamal.py` - `ElGamalSignature` class

### Digital Signature Concept

Digital signatures provide:
1. **Authentication**: Proves who signed the message
2. **Non-repudiation**: Signer cannot deny signing
3. **Integrity**: Detects any changes to the message

### ElGamal Signature Algorithm

#### Signature Generation
To sign message m:
1. Choose random k (coprime to p-1)
2. Compute r = g^k mod p
3. Compute s = (m - x×r) × k^(-1) mod (p-1)
4. Signature: (r, s)

#### Signature Verification
To verify signature (r, s) on message m:
1. Compute v1 = g^m mod p
2. Compute v2 = y^r × r^s mod p
3. Valid if v1 = v2

### API Reference

```python
class ElGamalSignature:
    @staticmethod
    def sign(message_hash: int, private_key: int, p: int, g: int) -> tuple[int, int]
    
    @staticmethod
    def verify(message_hash: int, signature: tuple[int, int], 
               public_key: int, p: int, g: int) -> bool
    
    @staticmethod
    def sign_message(message: str, keys: ElGamalKeyPair) -> tuple[int, int]
    
    @staticmethod
    def verify_message(message: str, signature: tuple[int, int], 
                      keys: ElGamalKeyPair) -> bool
```

### Usage Example

```python
from src.core.elgamal import ElGamal, ElGamalSignature

# Generate keys
keys = ElGamal.generate_keys(bits=16)

# Sign a message
message = "I transfer $100 to Bob"
signature = ElGamalSignature.sign_message(message, keys)
print(f"Signature: {signature}")

# Verify signature
is_valid = ElGamalSignature.verify_message(message, signature, keys)
print(f"Signature valid: {is_valid}")

# Tampering detection
tampered = "I transfer $999 to Bob"
is_valid = ElGamalSignature.verify_message(tampered, signature, keys)
print(f"Tampered message valid: {is_valid}")  # False
```

## Integration in SMS Project

These mathematical and cryptographic concepts work together:

```python
# Complete workflow using multiple labs
from src.core.elgamal import ElGamal, ElGamalSignature, KeyDistributionCenter
from src.core.hashing import MessageIntegrity

# 1. Set up KDC (Lab 10)
kdc = KeyDistributionCenter()
kdc.register_user("alice")
kdc.register_user("bob")

# 2. Generate ElGamal keys (Lab 09)
alice_keys = ElGamal.generate_keys()
bob_keys = ElGamal.generate_keys()

# 3. Alice signs and encrypts a message (Lab 11 + Lab 09)
message = "Meet at 3 PM"

# Sign message
signature = ElGamalSignature.sign_message(message, alice_keys)

# Encrypt message for Bob
message_int = int.from_bytes(message.encode(), 'big')
ciphertext = ElGamal.encrypt(message_int, bob_keys)

# 4. Bob verifies and decrypts
# Decrypt
decrypted_int = ElGamal.decrypt(ciphertext, bob_keys.private_key, bob_keys.p)
decrypted_msg = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big').decode()

# Verify signature
is_authentic = ElGamalSignature.verify_message(decrypted_msg, signature, alice_keys)

print(f"Message: {decrypted_msg}")
print(f"Signature valid: {is_authentic}")
```

## Security Considerations

### Strengths
- **Mathematical Security**: Based on hard mathematical problems
- **Public Key Cryptography**: No need to share secret keys
- **Digital Signatures**: Provides authentication and non-repudiation

### Limitations
- **Key Size**: Requires large keys for security (2048+ bits in practice)
- **Performance**: Slower than symmetric cryptography
- **Quantum Vulnerability**: Vulnerable to Shor's algorithm

### Best Practices
1. Use large key sizes (2048+ bits for production)
2. Use secure random number generators
3. Implement proper padding schemes
4. Combine with symmetric encryption for efficiency
5. Regular key rotation

## Real-World Applications

- **TLS/SSL**: Uses RSA/ECDSA signatures and key exchange
- **PGP/GPG**: Email encryption and signing
- **Bitcoin**: Digital signatures for transactions
- **Code Signing**: Software authenticity verification
- **PKI**: Public Key Infrastructure for certificates

## Testing All Labs

```python
def test_all_crypto_labs():
    """Test all cryptographic components"""
    
    # Test Lab 08 - Crypto Math
    from src.core.crypto_math import generate_prime, power_mod
    prime = generate_prime(8)
    assert is_prime(prime)
    
    # Test Lab 09 - ElGamal Encryption
    keys = ElGamal.generate_keys(16)
    msg = 12345
    c1, c2 = ElGamal.encrypt(msg, keys)
    decrypted = ElGamal.decrypt((c1, c2), keys.private_key, keys.p)
    assert msg == decrypted
    
    # Test Lab 10 - KDC
    kdc = KeyDistributionCenter()
    kdc.register_user("alice")
    kdc.register_user("bob")
    session_key, _, _ = kdc.request_session_key("alice", "bob")
    assert session_key is not None
    
    # Test Lab 11 - Digital Signatures
    message = "test message"
    signature = ElGamalSignature.sign_message(message, keys)
    assert ElGamalSignature.verify_message(message, signature, keys)
    
    print("All crypto labs tests passed!")

test_all_crypto_labs()
```