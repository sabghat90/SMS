# Testing Guide
## Secure Messaging System

---

## 🧪 Testing Strategy

This guide covers comprehensive testing of all system components.

---

## 1️⃣ Module Testing (Unit Tests)

### Test Authentication Module

```bash
python authentication.py
```

**Expected Output:**
```
=== User Authentication Module Tests ===

1. User Registration:
   Register Alice: User 'alice' registered successfully!
   Register Bob: User 'bob' registered successfully!
   Duplicate Alice: Username already exists

2. User Login:
   Alice login: Login successful! Session ID: a1b2c3d4...
   Bob wrong password: Invalid username or password

3. User Information:
   Alice info: {'created_at': '...', 'email': '...', 'login_count': 1}

4. List All Users:
   Registered users: ['alice', 'bob']
```

**✓ Pass Criteria:**
- All registrations succeed except duplicates
- Login works with correct credentials
- User info retrieved correctly
- Sessions created properly

---

### Test Cryptographic Math Module

```bash
python crypto_math.py
```

**Expected Output:**
```
=== Cryptographic Math Module Tests ===

1. GCD Tests:
   gcd(48, 18) = 6
   gcd(100, 35) = 5

2. Modular Inverse Tests:
   mod_inverse(3, 11) = 4
   Verification: (3 * 4) mod 11 = 1

3. Prime Generation:
   Generated 16-bit prime: [some prime number]
   Is prime? True

4. Modular Exponentiation:
   (5^13) mod 23 = [result]

5. Primitive Root:
   Primitive root of 23: 5
```

**✓ Pass Criteria:**
- GCD calculations correct
- Modular inverse correct (verify with multiplication)
- Generated number is actually prime
- Primitive root generates full group

---

### Test Classical Ciphers Module

```bash
python classical_ciphers.py
```

**Expected Output:**
```
=== Classical Ciphers Module Tests ===

1. Caesar Cipher (shift=3):
   Plaintext:  Hello World
   Encrypted:  Khoor Zruog
   Decrypted:  Hello World

2. Vigenère Cipher (key='SECRET'):
   Plaintext:  Attack at Dawn
   Encrypted:  Sxvrgd sx Wwgn
   Decrypted:  Attack at Dawn

3. Vigenère Cipher (key='KEY'):
   Plaintext:  CRYPTOGRAPHY
   Encrypted:  MBSXDYKVKZRC
   Decrypted:  CRYPTOGRAPHY
```

**✓ Pass Criteria:**
- Decrypted text matches original plaintext
- Non-alphabetic characters preserved
- Case preserved correctly
- Different keys produce different ciphertexts

---

### Test Modern Ciphers Module

```bash
python modern_ciphers.py
```

**Expected Output:**
```
=== Modern Ciphers Module Tests ===

1. XOR Stream Cipher:
   Plaintext:  Hello, this is a secret message!
   Encrypted:  [hex string]
   Decrypted:  Hello, this is a secret message!
   Key (hex):  [hex key]

2. Mini Block Cipher:
   Plaintext:  Confidential Data
   Encrypted:  [hex string]
   Decrypted:  Confidential Data
   Key (hex):  [hex key]
```

**✓ Pass Criteria:**
- Decryption recovers original plaintext exactly
- Ciphertext is in hexadecimal format
- Same key produces same ciphertext
- Different keys produce different ciphertexts

---

### Test Hashing Module

```bash
python hashing.py
```

**Expected Output:**
```
=== Hashing Module Tests ===

1. SHA-256 Hash Computation:
   Message: Hello, World!
   SHA-256: [64-character hex string]

2. Hash Verification:
   Original matches: True
   Tampered matches: False
   Tampered hash: [different hash]

3. HMAC (Message Authentication Code):
   Message: Hello, World!
   Key: secret_key_123
   HMAC: [hex string]
   HMAC Valid: True

4. Multiple Hash Algorithms:
   MD5: [32 chars]
   SHA1: [40 chars]
   SHA256: [64 chars]
   SHA512: [128 chars]

5. Message Authentication Code Class:
   Generated MAC: [hex string]
   Verification: True
   Tampered msg: False
```

**✓ Pass Criteria:**
- Same message produces same hash
- Different messages produce different hashes
- Tampering detected correctly
- HMAC verification works

---

### Test Blockchain Module

```bash
python blockchain.py
```

**Expected Output:**
```
=== Blockchain Module Tests ===

1. Creating Blockchain:
   Genesis block created
   Genesis hash: 00[...]

2. Adding Message Blocks:
   Block 1 added - Hash: 00[...]
   Block 2 added - Hash: 00[...]

3. Blockchain Validation:
   Valid: True
   Message: Blockchain is valid

4. Retrieve Alice's Messages:
   Alice has 2 message(s)
   - Block 1: alice -> bob
   - Block 2: bob -> alice

5. Blockchain Summary:
   Total blocks: 3
   Latest block index: 2
```

**✓ Pass Criteria:**
- Genesis block created successfully
- New blocks mined with leading zeros
- Chain validation passes
- User message retrieval works
- All hashes link correctly

---

### Test ElGamal & KDC Module

```bash
python elgamal.py
```

**Expected Output:**
```
=== ElGamal & KDC Module Tests ===

1. Key Generation:
   Alice's keys generated:
   - Prime (p): [large number]
   - Generator (g): [number]
   - Private key (x): [secret number]
   - Public key (y): [number]

2. Encrypt/Decrypt Integer:
   Original: 12345
   Ciphertext: ([c1], [c2])
   Decrypted: 12345
   Match: True

3. Encrypt/Decrypt Short String:
   Original: Hi
   Ciphertext: ([c1], [c2])
   Decrypted: Hi

4. Key Distribution Center (KDC):
   Registered users: ['alice', 'bob']
   Alice retrieved Bob's public key: [number]
   Alice -> Bob: 9999
   Bob decrypted: 9999
   Match: True
```

**✓ Pass Criteria:**
- Keys generated successfully
- Encryption/decryption successful
- Decrypted value matches original
- KDC stores and retrieves keys correctly

---

## 2️⃣ Integration Testing

### Test Complete Message Flow

**Test Case 1: Caesar Cipher Message**

```
Steps:
1. Run main.py
2. Login as alice (password: alice123)
3. Send message to bob
   - Message: "Test Message"
   - Method: Caesar Cipher
   - Shift: 5
4. Note the block hash
5. Logout
6. Login as bob (password: bob123)
7. View messages
8. Decrypt with shift=5
9. Verify hash matches

Expected Result:
✓ Message sent successfully
✓ Block added to blockchain
✓ Decryption successful
✓ Hash verification passed
```

**Test Case 2: Vigenère Cipher Message**

```
Steps:
1. Login as alice
2. Send message to bob
   - Message: "Secret Information"
   - Method: Vigenère Cipher
   - Key: "CRYPTO"
3. Logout
4. Login as bob
5. Decrypt with key "CRYPTO"

Expected Result:
✓ Message decrypted correctly
✓ Integrity check passed
```

**Test Case 3: XOR Stream Cipher**

```
Steps:
1. Login as alice
2. Send message to bob
   - Message: "Confidential Data 123"
   - Method: XOR Stream Cipher
   - Key: (random or custom)
3. SAVE THE KEY (hex format displayed)
4. Logout
5. Login as bob
6. Decrypt with saved key

Expected Result:
✓ Message decrypted correctly
✓ Hash verification successful
```

**Test Case 4: Mini Block Cipher**

```
Steps:
1. Login as alice
2. Send message to bob
   - Message: "Block cipher test"
   - Method: Mini Block Cipher
   - Key: (random or custom)
3. SAVE THE KEY
4. View blockchain
5. Verify block was added
6. Logout
7. Login as bob
8. Decrypt with saved key

Expected Result:
✓ Encryption successful
✓ Block mined and added
✓ Decryption successful
✓ Integrity verified
```

---

## 3️⃣ Security Testing

### Test 1: Password Security

```
Test: Weak password rejection
Steps:
1. Register user with password "123"
Expected: Rejected (< 6 characters)

Test: Password hashing
Steps:
1. Register user
2. Check if password is hashed (not stored plaintext)
Expected: Password hash stored, not plaintext
```

### Test 2: Session Management

```
Test: Invalid session
Steps:
1. Logout
2. Try to send message without logging in
Expected: Access denied or prompt to login

Test: Session isolation
Steps:
1. Login as alice
2. Can only see alice's messages
Expected: Cannot access bob's private messages
```

### Test 3: Blockchain Immutability

```
Test: Tampering detection
Steps:
1. Send several messages
2. Manually modify a block's data (in code)
3. Run blockchain verification
Expected: Verification fails, tampering detected
```

### Test 4: Hash Verification

```
Test: Integrity check
Steps:
1. Send message
2. Decrypt correctly
3. Manually change decrypted text
4. Verify hash
Expected: Hash verification fails
```

### Test 5: Encryption Key Security

```
Test: Wrong key decryption
Steps:
1. Encrypt with key "KEY1"
2. Try to decrypt with key "KEY2"
Expected: Decryption fails or produces garbage

Test: Missing key
Steps:
1. Try to decrypt without providing key
Expected: Decryption impossible
```

---

## 4️⃣ Stress Testing

### Test 1: Multiple Users

```
Steps:
1. Register 10 users
2. Each user sends 5 messages
3. Verify blockchain has 50 message blocks
4. Verify chain integrity

Expected:
✓ All blocks added successfully
✓ Chain remains valid
✓ No performance degradation
```

### Test 2: Long Messages

```
Steps:
1. Send message with 1000+ characters
2. Encrypt with each cipher type
3. Decrypt and verify

Note: ElGamal may have size limitations
Expected:
✓ Classical/modern ciphers handle long messages
✓ May need to split for ElGamal
```

### Test 3: Blockchain Size

```
Steps:
1. Add 100 blocks
2. Verify chain integrity
3. Check validation time

Expected:
✓ Chain remains valid
✓ Reasonable validation time
```

---

## 5️⃣ Edge Case Testing

### Test 1: Empty Message

```
Steps:
1. Try to send empty message
Expected: Rejected with error message
```

### Test 2: Special Characters

```
Steps:
1. Send message with special chars: !@#$%^&*()
2. Encrypt/decrypt with each method
Expected: All ciphers handle correctly
```

### Test 3: Unicode Characters

```
Steps:
1. Send message with emojis or unicode
2. Test with modern ciphers
Expected: XOR and Block ciphers handle correctly
Note: Classical ciphers may skip non-ASCII
```

### Test 4: Self-Messaging

```
Steps:
1. Try to send message to yourself
Expected: System prevents or handles gracefully
```

### Test 5: Non-existent Recipient

```
Steps:
1. Try to send to user not in KDC
Expected: Error message, message not sent
```

---

## 6️⃣ Performance Benchmarks

### Benchmark 1: Encryption Speed

```python
import time

# Test each cipher with 1000 encryptions
message = "Performance test message"
iterations = 1000

# Measure time for each cipher
# Expected: Modern ciphers faster than classical for long texts
```

### Benchmark 2: Blockchain Mining

```python
# Compare mining times with different difficulties
difficulty_1 = time to mine with difficulty=1
difficulty_2 = time to mine with difficulty=2
difficulty_3 = time to mine with difficulty=3

# Expected: Exponential increase in time
```

### Benchmark 3: Hash Computation

```python
# Measure SHA-256 hash speed
# Test with messages of varying lengths
# Expected: Linear time with message length
```

---

## 7️⃣ Test Checklist

### Basic Functionality
- [ ] User registration works
- [ ] User login works
- [ ] Session management works
- [ ] Caesar cipher encrypt/decrypt works
- [ ] Vigenère cipher encrypt/decrypt works
- [ ] XOR cipher encrypt/decrypt works
- [ ] Block cipher encrypt/decrypt works
- [ ] Hash computation works
- [ ] Hash verification works
- [ ] Blockchain creation works
- [ ] Block mining works
- [ ] Chain validation works
- [ ] ElGamal key generation works
- [ ] KDC registration works
- [ ] Message sending works
- [ ] Message viewing works

### Security Features
- [ ] Passwords are hashed
- [ ] Sessions are isolated
- [ ] Blockchain is immutable
- [ ] Tampering is detected
- [ ] Hash mismatches detected
- [ ] Wrong key decryption fails
- [ ] Access control enforced

### Edge Cases
- [ ] Empty messages rejected
- [ ] Special characters handled
- [ ] Non-existent users handled
- [ ] Duplicate usernames rejected
- [ ] Invalid keys rejected
- [ ] Chain breaks detected

### Integration
- [ ] Complete send/receive flow works
- [ ] All cipher types work end-to-end
- [ ] Multiple users can communicate
- [ ] Blockchain grows correctly
- [ ] All modules integrate properly

---

## 📊 Test Results Template

```
Test Date: _____________
Tester: _____________

Module Tests:
[ ] Authentication: PASS / FAIL
[ ] Crypto Math: PASS / FAIL
[ ] Classical Ciphers: PASS / FAIL
[ ] Modern Ciphers: PASS / FAIL
[ ] Hashing: PASS / FAIL
[ ] Blockchain: PASS / FAIL
[ ] ElGamal & KDC: PASS / FAIL

Integration Tests:
[ ] Caesar Flow: PASS / FAIL
[ ] Vigenère Flow: PASS / FAIL
[ ] XOR Flow: PASS / FAIL
[ ] Block Cipher Flow: PASS / FAIL

Security Tests:
[ ] Password Security: PASS / FAIL
[ ] Session Management: PASS / FAIL
[ ] Blockchain Immutability: PASS / FAIL
[ ] Hash Verification: PASS / FAIL
[ ] Encryption Security: PASS / FAIL

Notes:
_________________________________
_________________________________
_________________________________
```

---

## 🐛 Known Issues & Limitations

1. **ElGamal Message Size**: Limited by prime size (16-bit primes)
2. **Key Storage**: Keys not persisted (in-memory only)
3. **Blockchain Size**: No pruning mechanism
4. **Classical Ciphers**: Only handle ASCII alphabetic characters
5. **Demo Environment**: Not production-ready

---

## ✅ Acceptance Criteria

System passes testing if:
1. ✓ All module tests pass
2. ✓ At least 3 integration tests pass
3. ✓ All security tests pass
4. ✓ No critical bugs found
5. ✓ Documentation matches implementation
6. ✓ Edge cases handled gracefully

---

**Testing Guide Version:** 1.0  
**Last Updated:** October 31, 2025
