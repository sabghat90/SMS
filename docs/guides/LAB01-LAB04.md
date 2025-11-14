# Labs 01-04 - Programming Fundamentals and Classical Ciphers

## Overview

Labs 01-04 establish the programming fundamentals and introduce classical cryptographic ciphers that form the foundation for understanding more advanced cryptographic concepts.

## Lab 01 - Python Programming Basics

### Concepts Covered
- Variables and data types
- Control flow (if/else, loops)
- Functions and methods
- Input/output operations

### Implementation
**Module**: `src/core/authentication.py`

The authentication system demonstrates fundamental programming concepts:
- Dictionary data structures for user storage
- Conditional logic for validation
- Functions for user registration and login
- String manipulation and password hashing

### Usage Example

```python
from src.core.authentication import UserAuthentication

auth = UserAuthentication()

# Register a user
success, message = auth.register_user("alice", "password123")
print(message)

# Login
success, session_id = auth.login("alice", "password123")
if success:
    print(f"Login successful. Session: {session_id}")
```

## Lab 02 - Collections and Data Structures

### Concepts Covered
- Lists and arrays
- Dictionaries (hash maps)
- Sets for unique values
- Data structure operations (add, remove, search)

### Implementation
**Module**: `src/core/authentication.py`

User management uses dictionaries for efficient data storage:
- `users` dictionary: username -> user data mapping
- `active_sessions` dictionary: session_id -> username mapping
- Efficient O(1) lookups for authentication

### Data Structure Examples

```python
# User data structure
users = {
    "alice": {
        "password": "hashed_password",
        "email": "alice@example.com",
        "registration_date": "2024-01-01"
    }
}

# Session management
active_sessions = {
    "session_abc123": "alice",
    "session_def456": "bob"
}
```

## Lab 03 - Caesar Cipher

### Overview
The Caesar cipher is a substitution cipher that shifts each letter by a fixed number of positions in the alphabet.

**Module**: `src/core/classical_ciphers.py` - `CaesarCipher` class

### How It Works

1. Choose a shift value (e.g., 3)
2. For each letter in plaintext:
   - Shift forward by shift value
   - Wrap around at Z back to A
3. Non-alphabetic characters remain unchanged

Example with shift=3:
```
Plaintext:  HELLO
Shift:      +3 positions
Ciphertext: KHOOR
```

### API Reference

```python
class CaesarCipher:
    def __init__(self, shift=3)
    def encrypt(self, plaintext: str) -> str
    def decrypt(self, ciphertext: str) -> str
```

### Usage Example

```python
from src.core.classical_ciphers import CaesarCipher

cipher = CaesarCipher(shift=3)

plaintext = "HELLO WORLD"
encrypted = cipher.encrypt(plaintext)
print(f"Encrypted: {encrypted}")  # KHOOR ZRUOG

decrypted = cipher.decrypt(encrypted)
print(f"Decrypted: {decrypted}")  # HELLO WORLD
```

### Security Analysis

**Weaknesses**:
- Only 25 possible keys (easily brute-forced)
- Vulnerable to frequency analysis
- Does not hide patterns in text

**Why Study It**:
- Historical importance (used by Julius Caesar)
- Introduces encryption/decryption concepts
- Foundation for understanding substitution ciphers

## Lab 04 - Vigenere Cipher

### Overview
The Vigenere cipher is a polyalphabetic substitution cipher that uses a keyword to encrypt messages, making it more secure than Caesar cipher.

**Module**: `src/core/classical_ciphers.py` - `VigenereCipher` class

### How It Works

1. Choose a keyword (e.g., "KEY")
2. Repeat keyword to match plaintext length
3. For each letter:
   - Use corresponding keyword letter as shift value
   - Apply Caesar shift with that value

Example:
```
Plaintext:  HELLO WORLD
Keyword:    KEYKE YKEYK (repeated)
Shifts:     K=10, E=4, Y=24, K=10, E=4...
Ciphertext: RIJVS UYVJN
```

### API Reference

```python
class VigenereCipher:
    def __init__(self, key: str)
    def encrypt(self, plaintext: str) -> str
    def decrypt(self, ciphertext: str) -> str
```

### Usage Example

```python
from src.core.classical_ciphers import VigenereCipher

cipher = VigenereCipher(key="SECRET")

plaintext = "HELLO WORLD"
encrypted = cipher.encrypt(plaintext)
print(f"Encrypted: {encrypted}")

decrypted = cipher.decrypt(encrypted)
print(f"Decrypted: {decrypted}")  # HELLO WORLD
```

### Security Analysis

**Improvements over Caesar**:
- Multiple substitution alphabets
- Resistant to simple frequency analysis
- Key space grows with keyword length

**Weaknesses**:
- Vulnerable to Kasiski examination
- Vulnerable to Friedman test
- Patterns repeat at keyword intervals

**Historical Note**: Considered unbreakable for centuries ("le chiffre indéchiffrable") until broken by Charles Babbage in 1854.

## Comparison of Classical Ciphers

| Feature | Caesar | Vigenere |
|---------|--------|----------|
| **Key Space** | 25 keys | 26^n keys (n = key length) |
| **Encryption** | Single substitution | Polyalphabetic substitution |
| **Security** | Very weak | Weak (but better than Caesar) |
| **Speed** | Very fast | Fast |
| **Key Management** | Simple (one number) | Moderate (keyword) |

## Modern Relevance

While these classical ciphers are not secure by modern standards, they are important for:

1. **Education**: Understanding basic encryption concepts
2. **Foundation**: Building blocks for modern ciphers
3. **Analysis**: Learning cryptanalysis techniques
4. **History**: Appreciating evolution of cryptography

## Testing

Test both ciphers:

```python
# Test Caesar cipher
from src.core.classical_ciphers import CaesarCipher, VigenereCipher

# Caesar test
caesar = CaesarCipher(shift=13)  # ROT13
text = "ATTACK AT DAWN"
encrypted = caesar.encrypt(text)
assert caesar.decrypt(encrypted) == text

# Vigenere test
vigenere = VigenereCipher(key="CIPHER")
text = "HELLO WORLD"
encrypted = vigenere.encrypt(text)
assert vigenere.decrypt(encrypted) == text

print("All classical cipher tests passed")
```

## Further Reading

- "The Code Book" by Simon Singh (history of cryptography)
- "Applied Cryptography" by Bruce Schneier (Chapter 1)
- Learn about frequency analysis and cryptanalysis techniques
- Explore how classical ciphers were broken historically
