"""
Modern Ciphers Module
Lab 05 Concepts: XOR-based Stream Cipher and Mini Block Cipher
"""

import os


class XORStreamCipher:
    """
    XOR Stream Cipher: Uses XOR operation with a key stream
    Lab 05 Concept - Stream Cipher
    """
    
    def __init__(self, key=None):
        if key is None:
            # Generate random key
            self.key = os.urandom(16)
        elif isinstance(key, str):
            self.key = key.encode()
        else:
            self.key = key
    
    def _generate_keystream(self, length):
        """Generate keystream by repeating the key"""
        keystream = bytearray()
        for i in range(length):
            keystream.append(self.key[i % len(self.key)])
        return keystream
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using XOR stream cipher"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        keystream = self._generate_keystream(len(plaintext))
        ciphertext = bytearray()
        
        for i in range(len(plaintext)):
            ciphertext.append(plaintext[i] ^ keystream[i])
        
        return ciphertext.hex()
    
    def decrypt(self, ciphertext_hex):
        """Decrypt ciphertext using XOR stream cipher"""
        ciphertext = bytes.fromhex(ciphertext_hex)
        keystream = self._generate_keystream(len(ciphertext))
        plaintext = bytearray()
        
        for i in range(len(ciphertext)):
            plaintext.append(ciphertext[i] ^ keystream[i])
        
        return plaintext.decode('utf-8', errors='ignore')
    
    def get_key_hex(self):
        """Return key in hexadecimal format"""
        return self.key.hex()
    
    def set_key_from_hex(self, key_hex):
        """Set key from hexadecimal string"""
        self.key = bytes.fromhex(key_hex)


class MiniBlockCipher:
    """
    Mini Block Cipher: Simple substitution-permutation network
    Lab 05 Concept - Block Cipher
    Operates on 8-byte blocks with substitution and permutation rounds
    """
    
    def __init__(self, key=None):
        if key is None:
            # Generate random 8-byte key
            self.key = os.urandom(8)
        elif isinstance(key, str):
            # Pad or truncate key to 8 bytes
            key_bytes = key.encode()
            if len(key_bytes) < 8:
                key_bytes += b'\x00' * (8 - len(key_bytes))
            else:
                key_bytes = key_bytes[:8]
            self.key = key_bytes
        else:
            self.key = key
        
        # S-Box for substitution (simplified)
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
        ]
        
        # Inverse S-Box
        self.inv_sbox = [0] * 16
        for i, val in enumerate(self.sbox):
            self.inv_sbox[val % 16] = i
    
    def _pad(self, data):
        """PKCS7 padding to make data multiple of 8 bytes"""
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        pad_len = data[-1]
        return data[:-pad_len]
    
    def _substitute(self, block):
        """Apply S-box substitution"""
        return bytes([self.sbox[b % 16] for b in block])
    
    def _inv_substitute(self, block):
        """Apply inverse S-box substitution"""
        return bytes([self.inv_sbox[b % 16] for b in block])
    
    def _permute(self, block):
        """Simple permutation"""
        return bytes([block[i] for i in [7, 0, 5, 2, 6, 1, 4, 3]])
    
    def _inv_permute(self, block):
        """Inverse permutation"""
        return bytes([block[i] for i in [1, 5, 3, 7, 6, 2, 4, 0]])
    
    def _xor_with_key(self, block):
        """XOR block with key"""
        return bytes([block[i] ^ self.key[i] for i in range(8)])
    
    def _encrypt_block(self, block):
        """Encrypt a single 8-byte block"""
        # Round 1: XOR with key
        block = self._xor_with_key(block)
        
        # Round 2: Substitution
        block = self._substitute(block)
        
        # Round 3: Permutation
        block = self._permute(block)
        
        # Round 4: XOR with key again
        block = self._xor_with_key(block)
        
        return block
    
    def _decrypt_block(self, block):
        """Decrypt a single 8-byte block"""
        # Reverse Round 4
        block = self._xor_with_key(block)
        
        # Reverse Round 3
        block = self._inv_permute(block)
        
        # Reverse Round 2
        block = self._inv_substitute(block)
        
        # Reverse Round 1
        block = self._xor_with_key(block)
        
        return block
    
    def encrypt(self, plaintext):
        """Encrypt plaintext"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        # Pad plaintext
        padded = self._pad(plaintext)
        
        # Encrypt each block
        ciphertext = bytearray()
        for i in range(0, len(padded), 8):
            block = padded[i:i+8]
            encrypted_block = self._encrypt_block(block)
            ciphertext.extend(encrypted_block)
        
        return ciphertext.hex()
    
    def decrypt(self, ciphertext_hex):
        """Decrypt ciphertext"""
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Decrypt each block
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            decrypted_block = self._decrypt_block(block)
            plaintext.extend(decrypted_block)
        
        # Unpad
        plaintext = self._unpad(bytes(plaintext))
        
        return plaintext.decode('utf-8', errors='ignore')
    
    def get_key_hex(self):
        """Return key in hexadecimal format"""
        return self.key.hex()


# Testing
if __name__ == "__main__":
    print("=== Modern Ciphers Module Tests ===\n")
    
    # Test XOR Stream Cipher
    print("1. XOR Stream Cipher:")
    xor_cipher = XORStreamCipher(key="SECRETKEY")
    plaintext = "Hello, this is a secret message!"
    encrypted = xor_cipher.encrypt(plaintext)
    decrypted = xor_cipher.decrypt(encrypted)
    print(f"   Plaintext:  {plaintext}")
    print(f"   Encrypted:  {encrypted}")
    print(f"   Decrypted:  {decrypted}")
    print(f"   Key (hex):  {xor_cipher.get_key_hex()}\n")
    
    # Test Mini Block Cipher
    print("2. Mini Block Cipher:")
    block_cipher = MiniBlockCipher(key="BLOCKKEY")
    plaintext = "Confidential Data"
    encrypted = block_cipher.encrypt(plaintext)
    decrypted = block_cipher.decrypt(encrypted)
    print(f"   Plaintext:  {plaintext}")
    print(f"   Encrypted:  {encrypted}")
    print(f"   Decrypted:  {decrypted}")
    print(f"   Key (hex):  {block_cipher.get_key_hex()}\n")
