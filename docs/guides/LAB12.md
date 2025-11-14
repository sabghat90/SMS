# Lab 12 — Diffie-Hellman Key Exchange

## Overview

Lab 12 demonstrates **Diffie-Hellman (DH) key exchange**, a foundational protocol that allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself.

**Module**: `src/core/lab12_key_exchange.py`

## Concepts Demonstrated

### 1. Public Key Cryptography Foundation
- Alice and Bob each generate private/public key pairs
- Public keys can be safely shared
- Private keys must remain secret

### 2. Discrete Logarithm Problem
- Security relies on the difficulty of computing discrete logarithms
- Given g^x mod p, it's hard to find x
- Makes DH secure against passive eavesdropping

### 3. Shared Secret Computation
Both parties compute the same shared secret using different calculations:
- Alice computes: (Bob_public)^(Alice_private) mod p
- Bob computes: (Alice_public)^(Bob_private) mod p
- Result: Both get the same value!

### 4. Session Key Derivation
- Shared secret is hashed to create a session key
- Session key is used for symmetric encryption
- Combines efficiency of symmetric crypto with security of public key exchange

## API Reference

### Functions

```python
generate_private_key(bits: int = 128) -> int
```
Generate a random private key.

```python
generate_public_key(private_key: int, p: int, g: int) -> int
```
Compute public key using g^private mod p.

```python
compute_shared_secret(their_public: int, my_private: int, p: int) -> int
```
Compute the shared secret.

```python
derive_session_key(shared_secret: int, length: int = 32) -> bytes
```
Derive a session key from the shared secret using SHA-256.

### DHKeyExchange Class

```python
class DHKeyExchange:
    def __init__(self, p: Optional[int] = None, g: Optional[int] = None)
    def get_public_key(self) -> int
    def compute_shared_key(self, their_public_key: int) -> bytes
```

Object-oriented interface for easier integration.

## Usage Examples

### Basic Example

```python
from src.core import lab12_key_exchange as lab12

# Alice generates keys
alice_private = lab12.generate_private_key()
alice_public = lab12.generate_public_key(alice_private)

# Bob generates keys
bob_private = lab12.generate_private_key()
bob_public = lab12.generate_public_key(bob_private)

# Both compute shared secret
alice_shared = lab12.compute_shared_secret(bob_public, alice_private)
bob_shared = lab12.compute_shared_secret(alice_public, bob_private)

# Derive session keys
alice_key = lab12.derive_session_key(alice_shared)
bob_key = lab12.derive_session_key(bob_shared)

print(f"Keys match: {alice_key == bob_key}")
```

### Class-Based Example

```python
from src.core.lab12_key_exchange import DHKeyExchange

alice = DHKeyExchange()
bob = DHKeyExchange()

alice_session = alice.compute_shared_key(bob.get_public_key())
bob_session = bob.compute_shared_key(alice.get_public_key())

print(f"Session keys match: {alice_session == bob_session}")
```

## Running the Demo

```bash
# Run standalone demo
python examples/demo_lab12.py

# Run unit tests
python tests/test_lab12.py
```

## Real-World Applications

- **TLS/SSL**: Establishes session keys for HTTPS
- **SSH**: Secure shell connections
- **VPN**: Virtual private network key establishment
- **Signal/WhatsApp**: Modern messaging protocols use variants (X3DH)

## Security Considerations

### Educational Implementation
- Uses 160-bit prime for demo (production uses 2048+ bits)
- Not resistant to man-in-the-middle attacks (requires authentication)
- Vulnerable to quantum computers (see Lab 15 for post-quantum alternatives)

### Best Practices
- Always use authenticated DH (e.g., with certificates or signatures)
- Use standardized DH groups (RFC 3526, RFC 7919)
- Prefer ephemeral DH for forward secrecy (see Lab 15)

## Integration with SMS Project

Lab 12 can be integrated into the network layer for:
- Establishing session keys between client and server
- Replacing static key exchange with dynamic DH
- Adding forward secrecy to the messaging system

See `src/network/client.py` and `src/network/server.py` for integration points.

## References

- Original Paper: Diffie & Hellman (1976) "New Directions in Cryptography"
- RFC 2631: Diffie-Hellman Key Agreement Method
- RFC 7919: Negotiated Finite Field Diffie-Hellman Ephemeral Parameters
