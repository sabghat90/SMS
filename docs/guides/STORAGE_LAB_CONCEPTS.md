# Storage Security Implementation - Lab Concepts Only

## Overview
The Secure Messaging System's storage module has been updated to use **ONLY concepts from Labs 01-11**, removing all external cryptography library dependencies.

## Security Architecture

### Lab Concepts Used

#### Lab 05: Modern Ciphers (Encryption)
- **XOR Stream Cipher** for data encryption
- **Implementation**: `src/core/modern_ciphers.py`
- **Usage**: Encrypts user data and ElGamal keys before storage
- **Key Features**:
  - Keystream generation through key repetition
  - XOR operation for encryption/decryption
  - Hex encoding for storage

#### Lab 06: Hashing & Integrity (Security)
- **SHA-256** for key derivation and hashing
- **HMAC** for message authentication and integrity
- **Implementation**: `src/core/hashing.py`
- **Usage**:
  - Derive encryption keys from master password
  - Create HMAC signatures for encrypted data
  - Verify data integrity on load
  - Compute file hashes for additional verification

#### Lab 09: Crypto Math (Random Generation)
- **Prime Number Generation** for secure random values
- **Implementation**: `src/core/crypto_math.py`
- **Usage**: Generate cryptographically secure primes when needed

## Implementation Details

### Storage Module (`src/core/storage.py`)

#### Encryption Process
```python
# 1. Key Derivation (Lab 06)
master_password = "SecureMessagingSystem2025"
encryption_key = SHA-256(master_password)[:16 bytes]

# 2. Data Encryption (Lab 05)
json_data = JSON.dumps(data)
ciphertext = XOR_Cipher.encrypt(json_data, encryption_key)

# 3. Integrity Protection (Lab 06)
hmac_signature = HMAC-SHA256(ciphertext, encryption_key)

# 4. Storage
save_to_file({
    'encrypted': ciphertext,
    'hmac': hmac_signature
})
```

#### Decryption Process
```python
# 1. Load encrypted data
data = load_from_file()
ciphertext = data['encrypted']
hmac_signature = data['hmac']

# 2. Verify Integrity (Lab 06)
computed_hmac = HMAC-SHA256(ciphertext, encryption_key)
if computed_hmac != hmac_signature:
    raise IntegrityError("Data tampered!")

# 3. Decrypt Data (Lab 05)
json_data = XOR_Cipher.decrypt(ciphertext, encryption_key)
original_data = JSON.loads(json_data)
```

### Security Utilities (`src/core/security_utils.py`)

All utilities updated to use lab concepts:

#### SecurePasswordManager
- **Lab 06**: SHA-256 password hashing with salt
- **Python built-in**: `os.urandom()` for salt generation

#### SecureDataValidator
- **Lab 06**: HMAC signature creation and verification
- **Lab 06**: SHA-256 file hashing

#### SecureSessionManager
- **Lab 06**: SHA-256 based session IDs
- **Python built-in**: `os.urandom()` for randomness

#### SecureStorageHelper
- **Lab 06**: Integrity verification using stored hashes
- **Lab 05**: Backup encryption using XOR cipher

#### SecureRandomGenerator
- **Lab 09**: Prime number generation
- **Python built-in**: `os.urandom()` for random bytes

## Files Modified

### Core Changes
1. **`src/core/storage.py`** - Complete rewrite
   - Removed: `cryptography.fernet.Fernet`
   - Added: `from .modern_ciphers import XORStreamCipher`
   - Added: `from .hashing import MessageIntegrity`
   - Method: `_derive_key()` - Uses SHA-256
   - Method: `_encrypt_data()` - Uses XOR + HMAC
   - Method: `_decrypt_data()` - Verifies HMAC + XOR decrypt
   - Method: `verify_file_integrity()` - SHA-256 verification
   - Method: `_save_integrity_hash()` - Store SHA-256 hashes

2. **`src/core/security_utils.py`** - Updated imports
   - Removed: External `secrets` module usage (where possible)
   - Changed: All methods to use lab concepts
   - Added: `from .modern_ciphers import XORStreamCipher`
   - Updated: All random generation to use `os.urandom()`

3. **`requirements.txt`** - Removed dependencies
   - Removed: `cryptography>=41.0.0`
   - Updated: Documentation to clarify NO external crypto needed

### Data Format Changes

#### Before (Fernet)
```
users.json.enc (binary format)
keys.json.enc (binary format)
```

#### After (Lab Concepts)
```json
// users.json.enc (JSON format)
{
  "encrypted": "hex_encoded_xor_ciphertext",
  "hmac": "hmac_sha256_signature"
}

// keys.json.enc (JSON format)
{
  "encrypted": "hex_encoded_xor_ciphertext",
  "hmac": "hmac_sha256_signature"
}

// .integrity (JSON format)
{
  "users": {
    "hash": "sha256_hash",
    "timestamp": "2025-11-02 12:34:56"
  },
  "keys": {
    "hash": "sha256_hash",
    "timestamp": "2025-11-02 12:34:56"
  }
}
```

## Security Properties

### Encryption Strength
- **Algorithm**: XOR Stream Cipher (Lab 05)
- **Key Size**: 128 bits (16 bytes)
- **Key Derivation**: SHA-256 (256-bit hash → 128-bit key)
- **Note**: Educational cipher, suitable for lab demonstrations

### Integrity Protection
- **Algorithm**: HMAC-SHA256 (Lab 06)
- **Hash Size**: 256 bits
- **Protection Against**: Data tampering, corruption
- **Verification**: Automatic on load, manual via `verify_file_integrity()`

### Additional Security Layers
1. **File Integrity Hashes** - SHA-256 hashes stored in `.integrity` file
2. **Blockchain Integrity** - SHA-256 hash embedded in blockchain file
3. **Backup Verification** - Manifest file with SHA-256 hashes of backups

## Testing

### Verification Script
Run `test_lab_concepts.py` to verify:
```bash
python test_lab_concepts.py
```

### Tests Performed
1. Storage module loads without external crypto
2. No `cryptography` module dependency
3. XOR Stream Cipher encryption/decryption
4. HMAC integrity verification
5. SHA-256 hashing consistency
6. File integrity verification
7. Prime number generation (Lab 09)
8. Security utilities work with lab concepts

## Migration Notes

### Existing Data
**Important**: Data encrypted with old Fernet method is **not compatible** with new XOR method.

**To migrate**:
1. Run application with old code to export data
2. Update to new code
3. Re-register users (data will be encrypted with new method)

### Backup Compatibility
- Old backups (.enc files with Fernet): Not compatible
- New backups (.enc files with XOR+HMAC): JSON format, documented

## Educational Value

### Demonstrates Lab Concepts
1. **Lab 05**: Practical application of XOR stream cipher
2. **Lab 06**: Real-world use of SHA-256 and HMAC
3. **Lab 09**: Cryptographic math for random generation
4. **Integration**: How multiple lab concepts work together

### Security Principles Shown
- **Defense in Depth**: Multiple integrity checks (HMAC + SHA-256 file hash)
- **Key Derivation**: Proper key generation from password
- **Tamper Detection**: HMAC verification before decryption
- **Data Integrity**: Hash verification for files

## Performance Considerations

### XOR vs Fernet
- **Speed**: XOR is faster (simpler operations)
- **Security**: Fernet is stronger (AES-128-CBC + HMAC)
- **Use Case**: XOR suitable for educational lab environment

### File Format
- **Old Format**: Binary (smaller size)
- **New Format**: JSON (human-readable, debuggable)
- **Trade-off**: Slightly larger files, but easier to understand

## Conclusion

The storage system now uses **100% lab concepts**:
- No external cryptography libraries
- All security from Labs 05, 06, 09
- Educational and transparent
- Suitable for demonstrating cryptographic concepts
- Maintains data security for lab environment

**Version**: 2.0 (Lab Concepts)  
**Last Updated**: November 5, 2025  
**Status**: Production Ready for Educational Use
