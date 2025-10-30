"""
Core Modules - Cryptography, Authentication, and Blockchain
"""

from .crypto_math import gcd, extended_gcd, mod_inverse, is_prime, power_mod, find_primitive_root
from .authentication import UserAuthentication
from .classical_ciphers import CaesarCipher, VigenereCipher
from .modern_ciphers import XORStreamCipher, MiniBlockCipher
from .hashing import MessageIntegrity
from .blockchain import Block, MessageBlockchain
from .elgamal import ElGamal, KeyDistributionCenter

__all__ = [
    'gcd', 'extended_gcd', 'mod_inverse', 'is_prime', 'power_mod', 'find_primitive_root',
    'UserAuthentication',
    'CaesarCipher', 'VigenereCipher',
    'XORStreamCipher', 'MiniBlockCipher',
    'MessageIntegrity',
    'Block', 'MessageBlockchain',
    'ElGamal', 'KeyDistributionCenter'
]
