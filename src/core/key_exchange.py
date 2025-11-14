"""Lab 12 - Key Exchange (Diffie-Hellman)

Demonstrates Diffie-Hellman key exchange for establishing shared secrets
between two parties over an insecure channel. This is the foundation for
secure session key establishment in modern protocols like TLS.

Educational implementation - suitable for classroom demonstrations.
"""
import secrets
import hashlib
from typing import Tuple, Optional

# Demo prime (160-bit) and generator for educational use
# In production, use 2048+ bit primes or standardized groups
DEMO_P = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F
DEMO_G = 5


def generate_private_key(bits: int = 128) -> int:
    """
    Generate a private key (random integer).
    
    Args:
        bits: Number of random bits for the private key
        
    Returns:
        Random integer suitable for use as DH private key
    """
    return secrets.randbits(bits)


def generate_public_key(private_key: int, p: int = DEMO_P, g: int = DEMO_G) -> int:
    """
    Compute the public key using g^private mod p.
    
    Args:
        private_key: Secret exponent
        p: Prime modulus
        g: Generator
        
    Returns:
        Public key that can be safely shared
    """
    return pow(g, private_key, p)


def compute_shared_secret(their_public: int, my_private: int, p: int = DEMO_P) -> int:
    """
    Compute the shared secret using (their_public^my_private) mod p.
    
    Both parties compute the same value:
    - Alice computes: (Bob_public^Alice_private) mod p
    - Bob computes: (Alice_public^Bob_private) mod p
    
    Args:
        their_public: Other party's public key
        my_private: Your private key
        p: Prime modulus
        
    Returns:
        Shared secret (integer)
    """
    return pow(their_public, my_private, p)


def derive_session_key(shared_secret: int, length: int = 32) -> bytes:
    """
    Derive a session key from the shared secret using SHA-256.
    
    Args:
        shared_secret: The computed DH shared secret
        length: Desired key length in bytes
        
    Returns:
        Derived key suitable for encryption
    """
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return hashlib.sha256(secret_bytes).digest()[:length]


class DHKeyExchange:
    """
    Class-based interface for Diffie-Hellman key exchange.
    Suitable for integration into client-server protocols.
    """
    
    def __init__(self, p: Optional[int] = None, g: Optional[int] = None):
        """Initialize DH parameters."""
        self.p = p or DEMO_P
        self.g = g or DEMO_G
        self.private_key = generate_private_key()
        self.public_key = generate_public_key(self.private_key, self.p, self.g)
        self.shared_secret: Optional[int] = None
        self.session_key: Optional[bytes] = None
    
    def get_public_key(self) -> int:
        """Return the public key to send to the other party."""
        return self.public_key
    
    def compute_shared_key(self, their_public_key: int) -> bytes:
        """
        Compute shared secret and derive session key.
        
        Args:
            their_public_key: Other party's public key
            
        Returns:
            Derived session key (32 bytes)
        """
        self.shared_secret = compute_shared_secret(their_public_key, self.private_key, self.p)
        self.session_key = derive_session_key(self.shared_secret)
        return self.session_key


def demo() -> Tuple[int, int]:
    """
    Demonstrate full Diffie-Hellman key exchange between Alice and Bob.
    
    Returns:
        Tuple of (alice_shared_secret, bob_shared_secret) - should be equal
    """
    print("Lab 12: Diffie-Hellman Key Exchange Demo")
    print("=" * 50)
    
    # Alice generates her keys
    alice_private = generate_private_key()
    alice_public = generate_public_key(alice_private)
    print(f"Alice private key: {alice_private}")
    print(f"Alice public key: {alice_public}")
    
    # Bob generates his keys
    bob_private = generate_private_key()
    bob_public = generate_public_key(bob_private)
    print(f"\nBob private key: {bob_private}")
    print(f"Bob public key: {bob_public}")
    
    # Both compute the shared secret
    alice_shared = compute_shared_secret(bob_public, alice_private)
    bob_shared = compute_shared_secret(alice_public, bob_private)
    
    print(f"\nAlice computed shared secret: {alice_shared}")
    print(f"Bob computed shared secret: {bob_shared}")
    print(f"Secrets match: {alice_shared == bob_shared}")
    
    # Derive session keys
    alice_session_key = derive_session_key(alice_shared)
    bob_session_key = derive_session_key(bob_shared)
    print(f"\nDerived session keys (hex):")
    print(f"Alice: {alice_session_key.hex()}")
    print(f"Bob: {bob_session_key.hex()}")
    print(f"Session keys match: {alice_session_key == bob_session_key}")
    
    return alice_shared, bob_shared


if __name__ == "__main__":
    demo()
