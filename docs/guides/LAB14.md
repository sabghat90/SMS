# Lab 14 - Key Management

## Overview

Lab 14 demonstrates **secure key lifecycle management**, a critical aspect of cryptographic systems that is often overlooked. Poor key management is one of the most common causes of security breaches.

**Module**: `src/core/km.py`

## Concepts Demonstrated

### 1. Key Lifecycle
Keys go through distinct phases:
- **Creation**: Secure random generation
- **Active**: Normal usage period
- **Rotation**: Graceful replacement
- **Revocation**: Emergency invalidation
- **Destruction**: Secure erasure

### 2. Key Rotation
Why rotate keys?
- Limit damage from key compromise
- Meet compliance requirements (PCI-DSS, HIPAA)
- Reduce cryptanalysis window
- Best practice: rotate before suspected compromise

### 3. Key Revocation
Emergency key invalidation when:
- Key compromise suspected
- Employee termination
- Service decommissioning
- Security policy violation

### 4. Metadata Tracking
Track key information:
- Creation time
- Usage count
- Rotation history
- Revocation status and reason

## API Reference

### KeyManager Class

```python
class KeyManager:
    def __init__(self)
    def create_key(self, key_id: Optional[str] = None, length: int = 32, 
                   key_type: str = "symmetric") -> str
    def get_key(self, key_id: str) -> Optional[bytes]
    def rotate_key(self, old_key_id: str, new_key_id: Optional[str] = None) -> Optional[str]
    def revoke_key(self, key_id: str, reason: str = "unspecified") -> bool
    def list_keys(self, include_revoked: bool = False) -> List[str]
    def get_key_info(self, key_id: str) -> Optional[dict]
    def get_rotation_history(self) -> List[dict]
```

## Usage Examples

### Creating Keys

```python
from src.core.lab14_km import KeyManager

km = KeyManager()

# Auto-generated ID
key_id = km.create_key(key_type="session")

# Custom ID
key_id = km.create_key("master-key-2024", key_type="storage")

# Different key sizes
short_key = km.create_key(length=16)  # 128-bit
long_key = km.create_key(length=64)   # 512-bit
```

### Using Keys

```python
# Retrieve key material
key = km.get_key(key_id)

if key:
    # Use key for encryption/signing
    encrypted = encrypt_data(key, plaintext)
else:
    print("Key revoked or not found")
```

### Rotating Keys

```python
# Create new key, mark old as rotated
old_key_id = "key-2023"
new_key_id = km.rotate_key(old_key_id)

print(f"Rotated {old_key_id} -> {new_key_id}")

# Old key may still work temporarily (grace period)
# Explicitly revoke when rotation is complete
km.revoke_key(old_key_id, reason="rotation complete")
```

### Revoking Keys

```python
# Emergency revocation
km.revoke_key("compromised-key", reason="suspected breach")

# Scheduled revocation
km.revoke_key("old-api-key", reason="service deprecated")

# Verify revocation
key = km.get_key("compromised-key")
assert key is None  # Revoked keys return None
```

### Listing and Monitoring

```python
# List active keys
active = km.list_keys()
print(f"Active keys: {active}")

# Include revoked keys
all_keys = km.list_keys(include_revoked=True)

# Get detailed metadata
info = km.get_key_info(key_id)
print(f"Created: {info['created']}")
print(f"Usage count: {info['usage_count']}")
print(f"Age: {info['age_seconds']} seconds")

# Check rotation history
history = km.get_rotation_history()
for event in history:
    print(f"{event['old_key']} -> {event['new_key']} at {event['rotated_at']}")
```

## Running the Demo

```bash
# Run comprehensive key management demo
python examples/demo_lab14.py

# Run unit tests
python tests/test_lab14.py
```

## Real-World Key Management Systems

### Cloud KMS
- **AWS KMS**: Centralized key management for AWS services
- **Google Cloud KMS**: Multi-region key storage and rotation
- **Azure Key Vault**: Keys, secrets, and certificates management

### Hardware Security Modules (HSM)
- Physical devices for key storage
- FIPS 140-2 Level 3/4 certified
- Tamper-resistant hardware

### Enterprise Solutions
- HashiCorp Vault: Secrets management platform
- CyberArk: Privileged access management
- Thales (formerly Gemalto): HSM and key management

## Best Practices

### Key Generation
```python
# DO: Use cryptographically secure random
import secrets
key = secrets.token_bytes(32)

# DON'T: Use predictable random
import random  # INSECURE for crypto!
key = random.randbytes(32)  # NEVER DO THIS
```

### Key Storage
```python
# DO: Encrypt keys at rest
master_key = get_master_key()
encrypted_key = encrypt(master_key, key)
save_to_disk(encrypted_key)

# DON'T: Store keys in plaintext
with open("keys.txt", "w") as f:
    f.write(key.hex())  # INSECURE!
```

### Key Rotation Schedule
- **Session keys**: Every session
- **Encryption keys**: Every 90 days
- **Master keys**: Annually
- **Emergency**: Immediately upon suspected compromise

### Access Control
- Implement least privilege
- Log all key access
- Require authentication for key operations
- Use multi-party authorization for sensitive keys

## Integration with SMS Project

### Storage Layer Integration
```python
# storage.py can use KeyManager for encryption keys
from src.core.lab14_km import KeyManager

km = KeyManager()
storage_key_id = km.create_key(key_type="storage")

# Use key for file encryption
key = km.get_key(storage_key_id)
encrypted_data = xor_encrypt(key, data)

# Rotate keys periodically
new_key_id = km.rotate_key(storage_key_id)
```

### Network Layer Integration
```python
# server.py can manage session keys
km = KeyManager()

for client in clients:
    session_key_id = km.create_key(key_type="session")
    client.session_key = km.get_key(session_key_id)
    
    # Revoke on disconnect
    km.revoke_key(session_key_id, reason="client disconnected")
```

## Security Considerations

### Educational Implementation
- In-memory storage (production: use encrypted database or HSM)
- No persistence (production: save encrypted key metadata)
- Simple access control (production: RBAC, audit logging)

### Production Requirements
- Encrypt keys at rest
- Use HSM for master keys
- Implement key backup and recovery
- Maintain comprehensive audit logs
- Regular key rotation policies
- Disaster recovery procedures

## Compliance and Standards

### PCI-DSS Requirements
- Key rotation at least annually
- Dual control for master keys
- Separate keys for different environments

### HIPAA Security Rule
- Implement procedures for emergency key recovery
- Document key management processes
- Regular review of key access

### NIST Guidelines
- SP 800-57: Key Management Recommendations
- SP 800-133: Random Number Generation
- SP 800-171: Protecting Controlled Unclassified Information

## References

- NIST SP 800-57: Recommendation for Key Management
- ISO 27001: Information Security Management
- PCI-DSS Section 3.5: Key Management Requirements
- OWASP Key Management Cheat Sheet
