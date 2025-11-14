# Lab 15 — Post-Quantum Cryptography & Forward Secrecy

## Overview

Lab 15 demonstrates two critical modern security concepts that address emerging threats to cryptographic systems:

1. **Forward Secrecy**: Protecting past sessions even if long-term keys are compromised
2. **Post-Quantum Readiness**: Preparing for quantum computers that could break current cryptography

**Module**: `src/core/lab15_postquantum.py`

## Part A: Forward Secrecy

### Concept

**Forward Secrecy** (also called Perfect Forward Secrecy) ensures that compromise of long-term keys does NOT compromise past session keys.

### How It Works

Traditional approach:
```
Server has static private key
Client encrypts session key with server's public key
If server key is stolen -> ALL past sessions can be decrypted
```

Forward secrecy approach:
```
Generate ephemeral (temporary) keys for each session
Derive session key from ephemeral keys
Destroy ephemeral keys after session
If long-term key is stolen -> past sessions remain secure
```

### Why It Matters

Real-world scenarios:
- Server breach reveals long-term keys
- Adversary has recorded encrypted traffic
- Without forward secrecy: ALL past communications exposed
- With forward secrecy: Only current session exposed

### Implementation

```python
from src.core.lab15_postquantum import EphemeralDH

# Session 1
alice1 = EphemeralDH()
bob1 = EphemeralDH()

session1_key = alice1.compute_session_key(bob1.public_key)

# Destroy ephemeral keys (forward secrecy!)
alice1.destroy_keys()
bob1.destroy_keys()

# Session 2 uses NEW ephemeral keys
alice2 = EphemeralDH()
bob2 = EphemeralDH()

session2_key = alice2.compute_session_key(bob2.public_key)

# Sessions are independent and unlinkable
assert session1_key != session2_key
```

### EphemeralDH API

```python
class EphemeralDH:
    def __init__(self)  # Generate ephemeral keys
    def compute_session_key(self, their_public: int) -> bytes
    def destroy_keys(self)  # Achieve forward secrecy
```

## Part B: Post-Quantum Cryptography

### The Quantum Threat

**Shor's Algorithm** (1994):
- Quantum computers can break RSA, DH, ElGamal, ECC
- Not theoretical - quantum computers exist (IBM, Google, etc.)
- Current: ~100 qubits; Need: ~4000 for breaking RSA-2048
- Timeline: Unknown, but preparations needed NOW

**What's Vulnerable:**
- RSA encryption and signatures
- Diffie-Hellman key exchange
- Elliptic Curve Cryptography (ECC)
- ElGamal (Lab 09)

**What's Safe:**
- Symmetric encryption (AES, XOR with proper keys)
- Hash functions (SHA-256, SHA-3)
- HMAC

### Post-Quantum Algorithms

NIST selected standardized algorithms (2022):

| Algorithm | Type | Security Basis |
|-----------|------|----------------|
| CRYSTALS-Kyber | KEM | Lattice-based |
| CRYSTALS-Dilithium | Signature | Lattice-based |
| SPHINCS+ | Signature | Hash-based |
| FALCON | Signature | Lattice-based |

### Educational Implementation

**NOTE**: This module uses educational placeholders, NOT real PQ algorithms!

```python
from src.core.lab15_postquantum import PostQuantumKEM

# Bob generates PQ keypair
bob = PostQuantumKEM()
bob_public = bob.get_public_key()

# Alice encapsulates (creates shared secret + capsule)
alice = PostQuantumKEM()
capsule, alice_shared = alice.encapsulate(bob_public)

# Bob decapsulates (recovers shared secret)
bob_shared = bob.decapsulate(capsule)

# In real PQ-KEM: alice_shared == bob_shared
# This demo: educational placeholder only
```

### PostQuantumKEM API

```python
class PostQuantumKEM:
    def __init__(self)  # Generate PQ keypair
    def get_public_key(self) -> bytes
    def encapsulate(self, their_public_key: bytes) -> Tuple[bytes, bytes]
    def decapsulate(self, ciphertext: bytes) -> bytes
```

## Running the Demo

```bash
# Run both forward secrecy and post-quantum demos
python examples/demo_lab15.py

# Run unit tests
python tests/test_lab15.py
```

## Real-World Implementations

### Forward Secrecy in Practice

**TLS 1.3**
- Removes non-FS cipher suites
- Uses ephemeral DH or ECDH for all connections
- Session keys destroyed after use

**Signal Protocol**
- Double Ratchet algorithm
- New keys for every message
- Maximum forward secrecy

**WhatsApp, iMessage**
- Both use Signal Protocol
- Ephemeral keys for all messages

### Post-Quantum Migration

**Google Chrome**
- Hybrid post-quantum TLS (2023)
- Combines X25519 (classical) + Kyber (PQ)

**CloudFlare**
- Post-quantum TLS support
- Performance testing with Kyber

**Signal**
- PQXDH: Post-Quantum Extended DH
- Combines X25519 + Kyber for key agreement

## Migration Strategy

### Hybrid Approach (Recommended)

Combine classical and post-quantum:

```python
# Pseudocode for hybrid key exchange
classical_secret = diffie_hellman()
pq_secret = kyber_kem()
session_key = kdf(classical_secret || pq_secret)
```

Benefits:
- Security if PQ is broken -> classical still protects
- Security if quantum computer exists -> PQ still protects
- Best of both worlds

### Timeline

- **Now**: Inventory vulnerable systems
- **2024-2025**: Test PQ algorithms
- **2026-2030**: Gradual migration
- **2030+**: Full PQ deployment

## Comparison Table

### Classical vs Post-Quantum

| Aspect | Classical (RSA/DH) | Post-Quantum (Kyber) |
|--------|-------------------|----------------------|
| Key Size | 256 bytes (2048-bit RSA) | 1184 bytes (Kyber-768) |
| Ciphertext Size | 256 bytes | 1088 bytes |
| Security | Quantum-vulnerable | Quantum-resistant |
| Maturity | 40+ years | ~5 years |
| Speed | Fast | Comparable |

### Forward Secrecy Comparison

| Protocol | Forward Secrecy | Method |
|----------|----------------|--------|
| Static DH | No | Reuses same DH keys |
| Ephemeral DH | Yes | New keys each session |
| TLS 1.2 (RSA) | No | Static server key |
| TLS 1.3 | Yes | Mandatory ephemeral keys |

## Integration with SMS Project

### Network Layer Enhancement

```python
# server.py: Add ephemeral key exchange
from src.core.lab15_postquantum import EphemeralDH

class SecureConnection:
    def handshake(self):
        # Generate ephemeral keys for this connection
        self.dh = EphemeralDH()
        self.send_public_key(self.dh.public_key)
        
        their_public = self.receive_public_key()
        self.session_key = self.dh.compute_session_key(their_public)
        
        # Use session_key for this connection
        # Keys destroyed when connection closes
```

### Future-Proofing

```python
# Prepare for post-quantum transition
class HybridKeyExchange:
    def __init__(self):
        self.classical = EphemeralDH()
        self.pq = PostQuantumKEM()  # Replace with real Kyber later
        
    def derive_session_key(self, their_classical, their_pq):
        classical_secret = self.classical.compute_session_key(their_classical)
        pq_secret = self.pq.decapsulate(their_pq)
        return kdf(classical_secret + pq_secret)
```

## Security Considerations

### Forward Secrecy Requirements

1. **Generate fresh keys per session**
   ```python
   # DO
   for session in sessions:
       eph = EphemeralDH()  # New keys
   
   # DON'T
   eph = EphemeralDH()  # Reused keys = NO forward secrecy!
   for session in sessions:
       use(eph)
   ```

2. **Destroy keys properly**
   ```python
   # Zeroing memory
   self.private_key = 0
   self.public_key = 0
   ```

3. **Never log ephemeral keys**
   - Session keys must never be written to disk
   - Logging defeats forward secrecy

### Post-Quantum Considerations

1. **Larger key sizes**
   - PQ keys are 3-4x larger than classical
   - Plan for increased bandwidth

2. **Performance impact**
   - Test with realistic workloads
   - Consider hardware acceleration

3. **Standardization**
   - Use NIST-approved algorithms
   - Avoid experimental schemes

## Resources and References

### Standards

- NIST Post-Quantum Cryptography: [csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- RFC 8446: The TLS 1.3 Protocol (forward secrecy)
- RFC 9180: Hybrid Public Key Encryption (HPKE)

### Learning Resources

- "Post-Quantum Cryptography" by Bernstein, Buchmann, Dahmen
- NSA Cybersecurity Advisory: Quantum Computing and Post-Quantum Cryptography
- Google's Post-Quantum Cryptography Experiment

### Tools

- Open Quantum Safe (liboqs): PQ crypto library
- Bouncy Castle: Java PQ implementations
- PQClean: Clean C implementations of PQ algorithms

## Classroom Presentation Tips

### Demo 1: Forward Secrecy
1. Show two sessions with different ephemeral keys
2. Demonstrate that sessions are independent
3. Explain: "Even if server is hacked tomorrow, today's session is safe"

### Demo 2: Quantum Threat
1. Explain Shor's algorithm simply: "Quantum computers break DH/RSA"
2. Show key size comparison (classical vs PQ)
3. Discuss timeline: "Not if, but when"

### Discussion Points
- Why NSA/Google are already deploying PQ
- Hybrid approach: safety net during transition
- Career opportunity: PQ crypto is in high demand!
