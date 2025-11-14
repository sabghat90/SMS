# Secure Communication with Labs 12-15

This implementation demonstrates **real-world secure communication** using all concepts from Labs 12-15 integrated into a client-server messaging system.

## 🔐 Security Features

### Lab 12: Diffie-Hellman Key Exchange
- **What**: Secure key exchange without pre-shared secrets
- **Where**: Session establishment between client and server
- **How**: Ephemeral DH keys generate shared session key
- **Real-world**: TLS handshake, VPN key exchange

### Lab 13: AEAD (Authenticated Encryption)
- **What**: Combined confidentiality + integrity
- **Where**: All message encryption
- **How**: XOR stream cipher + HMAC-SHA256
- **Real-world**: AES-GCM (TLS 1.3), ChaCha20-Poly1305 (Signal)

### Lab 14: Key Management
- **What**: Key lifecycle (creation, rotation, revocation)
- **Where**: Session key rotation after heavy use
- **How**: Automatic rotation based on message count/age
- **Real-world**: AWS KMS, Azure Key Vault

### Lab 15: Forward Secrecy
- **What**: Past sessions secure even if keys compromised
- **Where**: Ephemeral keys destroyed after session
- **How**: Each session uses fresh DH keys
- **Real-world**: TLS 1.3 (mandatory), Signal protocol

## 📁 Files Overview

### Core Security Module
- **`src/core/secure_protocol.py`**: Complete security protocol integrating all labs
  - `SecureSession`: Manages single secure session
  - `SecureProtocol`: Protocol manager for multiple sessions

### Secure Client-Server (Recommended)
- **`secure_server.py`**: Enhanced server with full security (port 5556)
- **`secure_client.py`**: Enhanced client with full security

### Original Client-Server (Basic)
- **`server.py`**: Original server with basic encryption (port 5555)
- **`client.py`**: Original client with basic encryption

### Demonstrations
- **`demo_secure_communication.py`**: Interactive demo of all Lab 12-15 concepts
- **`examples/demo_lab12.py`**: Lab 12 standalone demo
- **`examples/demo_lab13.py`**: Lab 13 standalone demo
- **`examples/demo_lab14.py`**: Lab 14 standalone demo
- **`examples/demo_lab15.py`**: Lab 15 standalone demo

## 🚀 Quick Start

### Option 1: Run the Interactive Demo
```powershell
# Demonstrates all security concepts without server
python demo_secure_communication.py
```

**What you'll see:**
- Lab 12: DH key exchange demonstration
- Lab 13: AEAD encryption/decryption
- Lab 14: Key rotation process
- Lab 15: Forward secrecy explanation

### Option 2: Run Secure Client-Server
```powershell
# Terminal 1: Start secure server
python secure_server.py

# Terminal 2: Start first client (Alice)
python secure_client.py

# Terminal 3: Start second client (Bob)
python secure_client.py
```

**What happens:**
1. **Handshake (Lab 12)**: Client and server exchange ephemeral DH public keys
2. **Session Key**: Both derive same session key without transmitting it
3. **Secure Login**: Credentials encrypted with AEAD (Lab 13)
4. **Message Encryption**: All messages use AEAD with session key
5. **Key Rotation (Lab 14)**: Keys automatically rotate after many messages
6. **Session Cleanup (Lab 15)**: Keys destroyed on disconnect (forward secrecy)

## 📋 Usage Examples

### Secure Messaging Workflow

```
[Alice's Terminal]
1. Login (credentials encrypted with AEAD)
2. Choose "Send Secure Message"
3. Select Bob as receiver
4. Type message → encrypted with AEAD
5. Server stores in blockchain

[Bob's Terminal]
1. Login
2. Receives notification (encrypted)
3. Choose "View Messages"
4. Sees encrypted messages
5. Messages already decrypted (session key)
```

### Security Features in Action

```
[Session Establishment - Lab 12]
Alice: Generates ephemeral DH keys (private: secret, public: shared)
  → Sends public key to server
Server: Generates ephemeral DH keys
  → Sends public key to Alice
  → Computes shared secret from Alice's public + own private
Alice: Computes shared secret from Server's public + own private
Result: Both have identical session key!

[Message Encryption - Lab 13]
Alice: "Meet at 3 PM"
  → AEAD encrypt with session key
  → Produces ciphertext + authentication tag
  → Sends to server
Server: Receives encrypted message
  → AEAD decrypt with session key
  → Verifies authentication tag (tamper detection)
  → Stores/forwards message

[Key Rotation - Lab 14]
After 1000 messages or 1 hour:
  → Client/Server generate NEW ephemeral DH keys
  → Re-exchange and derive NEW session key
  → Old keys destroyed
  → Continue messaging with new key

[Forward Secrecy - Lab 15]
Session ends:
  → Ephemeral keys destroyed
  → Session key wiped from memory
  → Old encrypted messages cannot be decrypted
  → Even if long-term credentials stolen!
```

## 🔍 Security Protocol Flow

```
CLIENT                                SERVER
  |                                     |
  | 1. HANDSHAKE_INIT                  |
  |    - Ephemeral public key          |
  |----------------------------------->|
  |                                    |
  |                  2. HANDSHAKE_RESP |
  |    - Ephemeral public key          |
  |<-----------------------------------|
  |                                    |
  | Both compute session key (Lab 12)  |
  |                                    |
  | 3. SECURE_MESSAGE (LOGIN)          |
  |    - AEAD encrypted (Lab 13)       |
  |----------------------------------->|
  |                                    |
  |           4. SECURE_MESSAGE (OK)   |
  |    - AEAD encrypted                |
  |<-----------------------------------|
  |                                    |
  | 5. SECURE_MESSAGE (SEND MSG)       |
  |    - AEAD encrypted                |
  |----------------------------------->|
  |                                    |
  |   ... (key rotation after N msgs)  |
  |                                    |
  | 6. KEY_ROTATION                    |
  |    - New ephemeral keys (Lab 14)   |
  |<----------------------------------->|
  |                                    |
  | 7. Session ends                    |
  |    - Keys destroyed (Lab 15)       |
  |                                    |
```

## 🎓 Educational Value

### For Students
- See how theoretical concepts work in practice
- Understand why each security layer is needed
- Learn secure protocol design patterns
- Trace security through complete workflow

### For Demonstrations
1. **Show handshake**: Watch key exchange in real-time
2. **Tamper detection**: Modify encrypted message → fails authentication
3. **Key rotation**: Observe automatic key rotation
4. **Forward secrecy**: Destroy keys → old messages unrecoverable

## 🧪 Testing Security Features

### Test 1: Verify Key Exchange
```powershell
python demo_secure_communication.py
# Choose option 1 (Lab 12 demo)
# Observe: Both parties derive same key without transmitting it
```

### Test 2: Verify Tampering Detection
```powershell
python demo_secure_communication.py
# Choose option 2 (Lab 13 demo)
# Observe: Modified ciphertext causes decryption failure
```

### Test 3: Verify Key Rotation
```powershell
python demo_secure_communication.py
# Choose option 3 (Lab 14 demo)
# Observe: Keys rotate after message threshold
```

### Test 4: Verify Forward Secrecy
```powershell
python demo_secure_communication.py
# Choose option 4 (Lab 15 demo)
# Observe: Keys destroyed → past messages secure
```

## 📊 Security Guarantees

| Feature | Without Labs 12-15 | With Labs 12-15 |
|---------|-------------------|-----------------|
| Key Exchange | Pre-shared secrets required | Secure exchange over insecure channel |
| Confidentiality | Encryption only | Encryption + Authentication |
| Integrity | Separate verification | Built into encryption |
| Key Compromise | All messages exposed | Only current session exposed |
| Long Sessions | Single key vulnerable | Automatic key rotation |
| Past Messages | Decryptable if key stolen | Secure (forward secrecy) |

## 🔧 Configuration

### Adjust Security Parameters

Edit `src/core/secure_protocol.py`:

```python
# In SecureSession.__init__()
self.max_messages_before_rotation = 1000  # Rotate after N messages
self.max_session_age_seconds = 3600       # Rotate after 1 hour
```

### Change DH Parameters

Edit `src/core/lab12_key_exchange.py`:

```python
# For production: use 2048-bit prime
DEMO_P = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F  # 160-bit (demo)
DEMO_G = 5
```

## 🎯 Key Takeaways

### Lab 12 (DH Key Exchange)
✅ Establishes shared secrets without pre-sharing
✅ Foundation for all modern key exchange (TLS, SSH, VPN)
✅ Security relies on discrete logarithm problem

### Lab 13 (AEAD)
✅ Combines encryption + authentication efficiently
✅ Prevents tampering and forgery
✅ Modern standard (TLS 1.3 requires AEAD)

### Lab 14 (Key Management)
✅ Limits damage from key compromise
✅ Required for compliance (PCI-DSS, HIPAA)
✅ Best practice: rotate regularly

### Lab 15 (Forward Secrecy)
✅ Protects past communications
✅ Mandatory in TLS 1.3
✅ Essential for high-security applications

## 📚 Real-World Applications

- **TLS 1.3**: Uses all these concepts for HTTPS
- **Signal/WhatsApp**: Double ratchet algorithm (forward secrecy)
- **VPN Protocols**: WireGuard uses similar patterns
- **SSH**: Key exchange + session encryption
- **Enterprise Security**: KMS, credential rotation

## 🐛 Troubleshooting

### "Session not established"
- Make sure to connect() before other operations
- Check that handshake completed successfully

### "Handshake failed"
- Verify server is running
- Check firewall settings
- Ensure ports are available (5556 for secure server)

### "Key rotation failed"
- Normal after first few messages
- Server and client must both support rotation

## 📖 Further Reading

- `docs/guides/LAB12.md` - DH Key Exchange details
- `docs/guides/LAB13.md` - AEAD concepts
- `docs/guides/LAB14.md` - Key Management lifecycle
- `docs/guides/LAB15.md` - Forward Secrecy & Post-Quantum

## 🎬 Demo Videos

### Complete Workflow Demo
```powershell
python demo_secure_communication.py
# Choose option 5 for complete workflow
```

This demonstrates all 4 labs in sequence with detailed explanations.

---

**Created by**: Security & Cryptography Course
**Purpose**: Educational demonstration of modern secure communication
**Note**: This is for learning. Production systems should use established libraries (TLS, Signal Protocol, etc.)
