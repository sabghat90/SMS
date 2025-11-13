# Lab Concepts Mapping
## Detailed Mapping of Labs 01-11 to Code Implementation

---

## Lab 01: Python Basics

### Concepts Covered
- Variables and data types
- Functions
- Control structures (if/else, loops)
- Basic I/O

### Implementation Locations

**authentication.py**
```python
# Line 12-13: Variables
self.users = {}
self.active_sessions = {}

# Line 15-17: Functions
def _hash_password(self, password):
    return hashlib.sha256(password.encode()).hexdigest()

# Line 24-30: Conditionals
if not username or not password:
    return False, "Username and password cannot be empty"

if username in self.users:
    return False, "Username already exists"
```

**All modules**
- Function definitions throughout
- Variable assignments
- Conditional logic in all validation code
- Loops in encryption/decryption algorithms

---

## Lab 02: Collections (Dictionaries)

### Concepts Covered
- Dictionary operations
- Key-value pairs
- Dictionary methods (get, keys, items)
- Nested dictionaries

### Implementation Locations

**authentication.py**
```python
# Line 12: Dictionary for user storage
self.users = {}

# Line 35-40: Nested dictionary
self.users[username] = {
    'password_hash': self._hash_password(password),
    'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    'email': email,
    'login_count': 0
}

# Line 57-60: Dictionary operations
self.active_sessions[session_id] = {
    'username': username,
    'login_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
}

# Line 75: Dictionary get method
if username not in self.users:
    return None
```

**elgamal.py**
```python
# Line 114-119: Dictionary for KDC
self.public_keys = {}
self.key_registry = {}

# Line 129-135: Nested dictionary
self.key_registry[username] = {
    'p': key_pair.p,
    'g': key_pair.g,
    'public_key': key_pair.public_key,
    'registered_at': None
}
```

**main.py**
```python
# Line 19: Dictionary for user keys
self.user_keys = {}

# Storing ElGamal keys
self.user_keys[username] = key_pair
```

---

## Lab 03: Caesar Cipher

### Concepts Covered
- Substitution cipher
- Character shifting
- ASCII manipulation
- Modular arithmetic (shift with wrap-around)

### Implementation Locations

**classical_ciphers.py**
```python
# Lines 8-37: Caesar Cipher Class
class CaesarCipher:
    def __init__(self, shift=3):
        self.shift = shift
    
    def encrypt(self, plaintext):
        ciphertext = ""
        for char in plaintext:
            if char.isalpha():
                # Determine ASCII offset
                ascii_offset = ord('A') if char.isupper() else ord('a')
                # Shift with modular arithmetic
                shifted = (ord(char) - ascii_offset + self.shift) % 26
                ciphertext += chr(shifted + ascii_offset)
            else:
                ciphertext += char
        return ciphertext
```

**Key Concepts Demonstrated:**
- Character iteration
- ASCII value manipulation with `ord()` and `chr()`
- Modular arithmetic `% 26` for wrap-around
- Preserving case and non-alphabetic characters

---

## Lab 04: Vigenère Cipher

### Concepts Covered
- Polyalphabetic substitution
- Keyword-based encryption
- Key repetition
- Multiple Caesar shifts

### Implementation Locations

**classical_ciphers.py**
```python
# Lines 40-95: Vigenère Cipher Class
class VigenereCipher:
    def __init__(self, key):
        self.key = key.upper()
    
    def encrypt(self, plaintext):
        ciphertext = ""
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                
                # Get key character for this position
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # Apply shift
                shifted = (ord(char) - ascii_offset + key_shift) % 26
                ciphertext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                ciphertext += char
        
        return ciphertext
```

**Key Concepts Demonstrated:**
- Key repetition with `key_index % len(self.key)`
- Different shift for each character
- Keyword-based shifting

---

## Lab 05: Modern Ciphers

### Concepts Covered
- Stream ciphers (XOR-based)
- Block ciphers (Substitution-Permutation Network)
- Keystream generation
- Padding schemes (PKCS7)

### Implementation Locations

#### XOR Stream Cipher
**modern_ciphers.py**
```python
# Lines 9-49: XOR Stream Cipher
class XORStreamCipher:
    def _generate_keystream(self, length):
        keystream = bytearray()
        for i in range(length):
            keystream.append(self.key[i % len(self.key)])
        return keystream
    
    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        keystream = self._generate_keystream(len(plaintext))
        ciphertext = bytearray()
        
        # XOR operation
        for i in range(len(plaintext)):
            ciphertext.append(plaintext[i] ^ keystream[i])
        
        return ciphertext.hex()
```

**Key Concepts:**
- XOR operation (`^`)
- Keystream generation
- Byte-level operations

#### Mini Block Cipher
**modern_ciphers.py**
```python
# Lines 52-181: Mini Block Cipher
class MiniBlockCipher:
    def _pad(self, data):
        # PKCS7 padding
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)
    
    def _substitute(self, block):
        # S-box substitution
        return bytes([self.sbox[b % 16] for b in block])
    
    def _permute(self, block):
        # Permutation
        return bytes([block[i] for i in [7, 0, 5, 2, 6, 1, 4, 3]])
    
    def _encrypt_block(self, block):
        # Substitution-Permutation Network
        block = self._xor_with_key(block)      # Round 1: XOR
        block = self._substitute(block)         # Round 2: S-box
        block = self._permute(block)            # Round 3: Permute
        block = self._xor_with_key(block)      # Round 4: XOR
        return block
```

**Key Concepts:**
- S-box substitution
- Permutation
- Multiple rounds
- PKCS7 padding

---

## Lab 06: Hashing & Integrity

### Concepts Covered
- SHA-256 hash function
- Message integrity verification
- HMAC (Hash-based Message Authentication Code)
- Hash comparison

### Implementation Locations

**hashing.py**
```python
# Lines 11-21: SHA-256 Hash Computation
@staticmethod
def compute_hash(message):
    if isinstance(message, str):
        message = message.encode()
    
    hash_obj = hashlib.sha256(message)
    return hash_obj.hexdigest()

# Lines 23-31: Hash Verification
@staticmethod
def verify_hash(message, expected_hash):
    computed_hash = MessageIntegrity.compute_hash(message)
    is_valid = (computed_hash == expected_hash)
    return is_valid, computed_hash

# Lines 33-45: HMAC
@staticmethod
def compute_hmac(message, key):
    if isinstance(message, str):
        message = message.encode()
    if isinstance(key, str):
        key = key.encode()
    
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()
```

**Usage in main.py**
```python
# Line 189: Hash before encryption
message_hash = MessageIntegrity.compute_hash(plaintext)

# Line 280: Hash verification after decryption
is_valid, computed_hash = MessageIntegrity.verify_hash(plaintext, original_hash)
```

**Key Concepts:**
- One-way hash functions
- Pre-encryption hashing
- Post-decryption verification
- Tamper detection

---

## Lab 07: Blockchain

### Concepts Covered
- Block structure
- Chain linking (previous hash)
- Proof of Work (mining)
- Immutability
- Chain validation

### Implementation Locations

**blockchain.py**
```python
# Lines 11-60: Block Class
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash  # Chain linking
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        # Hash of entire block
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty=2):
        # Proof of Work
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        return self.hash

# Lines 126-145: Chain Validation
def is_chain_valid(self):
    for i in range(1, len(self.chain)):
        current_block = self.chain[i]
        previous_block = self.chain[i - 1]
        
        # Verify current block's hash
        if current_block.hash != current_block.calculate_hash():
            return False, f"Block {i} has invalid hash"
        
        # Verify link to previous block
        if current_block.previous_hash != previous_block.hash:
            return False, f"Block {i} has invalid previous hash"
    
    return True, "Blockchain is valid"
```

**Usage in main.py**
```python
# Line 200: Adding message to blockchain
block = self.blockchain.add_message_block(
    sender=self.current_username,
    receiver=receiver,
    ciphertext=str(ciphertext),
    message_hash=message_hash,
    encryption_method=encryption_method
)
```

**Key Concepts:**
- Block chaining
- Hash pointers
- Proof of Work mining
- Tamper evidence
- Immutable ledger

---

## Lab 09: ElGamal Encryption

### Concepts Covered
- Public-key cryptography
- ElGamal key generation
- Discrete logarithm problem
- Asymmetric encryption/decryption

### Implementation Locations

**elgamal.py**
```python
# Lines 21-48: ElGamal Key Generation
@staticmethod
def generate_keys(bits=16):
    # Generate large prime p
    p = generate_prime(bits)
    
    # Find primitive root g of p
    g = find_primitive_root(p)
    
    # Generate private key (random number 1 < x < p-1)
    private_key = random.randint(2, p - 2)
    
    # Compute public key: y = g^x mod p
    public_key = power_mod(g, private_key, p)
    
    return ElGamalKeyPair(p, g, private_key, public_key)

# Lines 50-78: ElGamal Encryption
@staticmethod
def encrypt(plaintext, public_key_pair):
    p = public_key_pair.p
    g = public_key_pair.g
    y = public_key_pair.public_key
    
    # Convert to integer
    m = int.from_bytes(plaintext.encode(), 'big')
    
    # Choose random k
    k = random.randint(2, p - 2)
    
    # c1 = g^k mod p
    c1 = power_mod(g, k, p)
    
    # c2 = m * y^k mod p
    c2 = (m * power_mod(y, k, p)) % p
    
    return (c1, c2)

# Lines 80-101: ElGamal Decryption
@staticmethod
def decrypt(ciphertext, private_key_pair):
    c1, c2 = ciphertext
    p = private_key_pair.p
    x = private_key_pair.private_key
    
    # Compute s = c1^x mod p
    s = power_mod(c1, x, p)
    
    # Compute s^-1 mod p
    s_inv = mod_inverse(s, p)
    
    # Recover plaintext: m = c2 * s^-1 mod p
    m = (c2 * s_inv) % p
    
    return m
```

**Key Concepts:**
- Public/private key pairs
- One-way function (discrete log)
- Random element k
- Modular exponentiation

---

## Lab 11: Key Distribution

### Concepts Covered
- Key Distribution Center (KDC)
- Public key registry
- Key exchange without direct communication
- Centralized key management

### Implementation Locations

**elgamal.py**
```python
# Lines 123-179: Key Distribution Center
class KeyDistributionCenter:
    def __init__(self):
        # Store public keys for all users
        self.public_keys = {}
        self.key_registry = {}
    
    def register_user(self, username, key_pair):
        # Register user's public key
        self.public_keys[username] = key_pair
        self.key_registry[username] = {
            'p': key_pair.p,
            'g': key_pair.g,
            'public_key': key_pair.public_key,
            'registered_at': None
        }
        return True
    
    def get_public_key(self, username):
        # Retrieve user's public key
        return self.public_keys.get(username)
    
    def is_user_registered(self, username):
        # Check registration
        return username in self.public_keys
    
    def list_registered_users(self):
        # Get all users
        return list(self.public_keys.keys())
```

**Usage in main.py**
```python
# Line 52-55: Register public key with KDC
print("\nGenerating ElGamal key pair...")
key_pair = ElGamal.generate_keys(bits=16)
self.user_keys[username] = key_pair

# Register public key with KDC
self.kdc.register_user(username, key_pair)

# Line 178: Retrieve recipient's public key
if not self.kdc.is_user_registered(receiver):
    print(f" User '{receiver}' not found in KDC")
    return
```

**Key Concepts:**
- Centralized key server
- Public key storage
- Key lookup service
- Trust model

---

## Supporting Module: Cryptographic Math

### Concepts Used Across All Labs
Located in **crypto_math.py**

```python
# Lines 8-13: GCD (Euclidean Algorithm)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Lines 29-37: Modular Inverse (Extended Euclidean)
def mod_inverse(a, m):
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist")
    return (x % m + m) % m

# Lines 40-69: Prime Testing (Miller-Rabin)
def is_prime(n, k=5):
    # Probabilistic primality test
    # ... implementation ...

# Lines 72-83: Prime Generation
def generate_prime(bits=16):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= 1  # Make odd
        candidate |= (1 << (bits - 1))  # Set high bit
        
        if is_prime(candidate):
            return candidate

# Lines 86-99: Modular Exponentiation
def power_mod(base, exponent, modulus):
    # Fast exponentiation: (base^exp) mod m
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result

# Lines 102-126: Primitive Root Finding
def find_primitive_root(p):
    # Find generator for multiplicative group Z*p
    # ... implementation ...
```

**Used in:**
- Lab 09 (ElGamal): prime generation, modular inverse, power_mod
- Lab 05 (Ciphers): modular arithmetic concepts
- Lab 03 & 04 (Classical): modulo 26 operations

---

## Concept Integration Summary

| Lab | Module | Key Function/Class | Line Numbers |
|-----|--------|-------------------|--------------|
| Lab 01 | All modules | Functions, variables, control flow | Throughout |
| Lab 02 | authentication.py | `self.users` dictionary | 12-40 |
| Lab 02 | elgamal.py | `self.public_keys` dictionary | 114-119 |
| Lab 03 | classical_ciphers.py | `CaesarCipher` class | 8-37 |
| Lab 04 | classical_ciphers.py | `VigenereCipher` class | 40-95 |
| Lab 05 | modern_ciphers.py | `XORStreamCipher` class | 9-49 |
| Lab 05 | modern_ciphers.py | `MiniBlockCipher` class | 52-181 |
| Lab 06 | hashing.py | `MessageIntegrity.compute_hash()` | 15-21 |
| Lab 06 | hashing.py | `MessageIntegrity.verify_hash()` | 23-31 |
| Lab 07 | blockchain.py | `Block` class | 11-60 |
| Lab 07 | blockchain.py | `MessageBlockchain` class | 63-203 |
| Lab 09 | elgamal.py | `ElGamal.generate_keys()` | 21-48 |
| Lab 09 | elgamal.py | `ElGamal.encrypt()` | 50-78 |
| Lab 09 | elgamal.py | `ElGamal.decrypt()` | 80-101 |
| Lab 11 | elgamal.py | `KeyDistributionCenter` class | 123-179 |

---

## Learning Path Through Code

### Beginner Level (Labs 01-02)
1. Start with **authentication.py** - understand dictionaries and functions
2. Look at variable usage in all modules
3. Study control flow in validation functions

### Intermediate Level (Labs 03-06)
1. **classical_ciphers.py** - understand substitution
2. **modern_ciphers.py** - learn XOR and block operations
3. **hashing.py** - study integrity verification

### Advanced Level (Labs 07, 09, 11)
1. **blockchain.py** - understand chain structure and mining
2. **crypto_math.py** - study mathematical foundations
3. **elgamal.py** - learn public-key cryptography and KDC

### Integration Level
1. **main.py** - see how all components work together
2. Study the complete message flow
3. Understand security architecture

---

**Last Updated:** Nov 12, 2025  
**Version:** 1.1
