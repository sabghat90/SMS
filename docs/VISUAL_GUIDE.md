# Visual Guide: Labs 12-15 Security Concepts

## 🎨 Visual Representations

### 1. Diffie-Hellman Key Exchange (Lab 12)

```
┌─────────────────────────────────────────────────────────────────┐
│                    DH KEY EXCHANGE PROTOCOL                      │
└─────────────────────────────────────────────────────────────────┘

ALICE                                                    BOB
  │                                                       │
  │ 1. Choose private key                                │
  │    a = random(128 bits)                              │
  │    Keep SECRET!                                      │
  │                                                       │
  │                          2. Choose private key       │
  │                             b = random(128 bits)     │
  │                             Keep SECRET!             │
  │                                                       │
  │ 3. Compute public key                                │
  │    A = g^a mod p                                     │
  │                                                       │
  │                          4. Compute public key       │
  │                             B = g^b mod p            │
  │                                                       │
  │ 5. Send A                                            │
  │ ────────────────────────────────────────────────────>│
  │                                                       │
  │                                          6. Send B   │
  │ <────────────────────────────────────────────────────│
  │                                                       │
  │ 7. Compute shared secret                             │
  │    s = B^a mod p                                     │
  │      = (g^b)^a mod p                                 │
  │      = g^(ab) mod p                                  │
  │                                                       │
  │                          8. Compute shared secret    │
  │                             s = A^b mod p            │
  │                               = (g^a)^b mod p        │
  │                               = g^(ab) mod p         │
  │                                                       │
  │ 9. Both have same secret: s = g^(ab) mod p          │
  │                                                       │
  │ 10. Derive session key                               │
  │     session_key = SHA256(s)                          │
  │                                                       │
  │         🔒 SECURE CHANNEL ESTABLISHED 🔒             │
  │                                                       │

EVE (Eavesdropper) sees:
  - Public values: g, p, A, B
  - Cannot compute: a, b, or s = g^(ab) mod p
  - Problem: Discrete Logarithm (computationally hard)
```

### 2. AEAD Encryption (Lab 13)

```
┌─────────────────────────────────────────────────────────────────┐
│            AEAD: AUTHENTICATED ENCRYPTION WITH AAD               │
└─────────────────────────────────────────────────────────────────┘

ENCRYPTION FLOW:
┌──────────────┐
│  Plaintext   │  "Hello Bob, meet at 3 PM"
└──────┬───────┘
       │
       │  ┌─────────────┐
       └─>│   Encrypt   │<─── Session Key (from DH)
          │ (XOR Stream)│
          └──────┬──────┘
                 │
                 ▼
          ┌──────────────┐
          │  Ciphertext  │  "a3b7c9d2e4f8..."
          └──────┬───────┘
                 │
                 │  ┌──────────────┐
                 └─>│              │
                    │  Compute Tag │<─── Session Key
┌──────────────┐   │   (HMAC)     │
│ Metadata     │──>│              │
│ (AAD)        │   └──────┬───────┘
│ - from: Alice│          │
│ - to: Bob    │          ▼
│ - timestamp  │   ┌──────────────┐
└──────────────┘   │ Auth Tag     │  "f3e8d7c6b5a4..."
                   └──────────────┘

SEND: Ciphertext + Tag + Nonce + AAD

DECRYPTION FLOW:
┌──────────────┐
│  Ciphertext  │  "a3b7c9d2e4f8..."
└──────┬───────┘
       │
       │  ┌──────────────┐
       └─>│ Verify Tag   │<─── Session Key + AAD
          │   (HMAC)     │
          └──────┬───────┘
                 │
            ┌────┴────┐
            │         │
        VALID?    INVALID?
            │         │
            ▼         ▼
     ┌──────────┐  ┌──────────┐
     │ Decrypt  │  │ REJECT!  │
     │   (XOR)  │  │ Tampered │
     └────┬─────┘  └──────────┘
          │
          ▼
     ┌──────────┐
     │Plaintext │  "Hello Bob, meet at 3 PM"
     └──────────┘

🛡️ GUARANTEES:
  ✓ Confidentiality (encryption)
  ✓ Integrity (tag verification)
  ✓ Authentication (only key holder can create valid tag)
```

### 3. Key Rotation (Lab 14)

```
┌─────────────────────────────────────────────────────────────────┐
│                      KEY ROTATION LIFECYCLE                      │
└─────────────────────────────────────────────────────────────────┘

SESSION TIMELINE:

t=0s         SESSION START
             ├─ Generate ephemeral DH keys
             ├─ Exchange and compute session_key_1
             └─ message_count = 0

t=1s         ├─ Send message #1 (encrypted with key_1)
             ├─ Send message #2
t=2s         ├─ Send message #3
             ├─ ...
             └─ message_count++

t=300s       ├─ Send message #998
t=301s       ├─ Send message #999
t=302s       ├─ Send message #1000
             │
             └─ ROTATION TRIGGERED!
                ├─ message_count >= 1000 OR
                └─ session_age >= 3600s

             ROTATION PROCESS:
             ├─ 1. Generate NEW ephemeral DH keys
             ├─ 2. Destroy OLD ephemeral keys
             ├─ 3. Exchange NEW public keys
             ├─ 4. Compute NEW session_key_2
             ├─ 5. Reset message_count = 0
             └─ 6. Continue with key_2

t=303s       ├─ Send message #1 (encrypted with key_2)
             ├─ Send message #2
             └─ ...

t=3600s      SESSION END
             ├─ Destroy all ephemeral keys
             ├─ Wipe session_key_2
             └─ FORWARD SECRECY ACHIEVED!

WHY ROTATE?
  ✓ Limit data encrypted with single key
  ✓ Reduce cryptanalysis window
  ✓ Comply with regulations (PCI-DSS: 90 days)
  ✓ Limit damage from key compromise
```

### 4. Forward Secrecy (Lab 15)

```
┌─────────────────────────────────────────────────────────────────┐
│                       FORWARD SECRECY                            │
└─────────────────────────────────────────────────────────────────┘

SCENARIO: Eve records encrypted traffic, later steals long-term keys

WITHOUT FORWARD SECRECY:
═══════════════════════════════════════════════════════════════

DAY 1:
Alice ────encrypted messages────> Bob
  ^                                  ^
  │                                  │
Static keys                    Static keys
(same forever)                 (same forever)

Eve records all traffic: ████████████████████

DAY 7: Eve compromises Alice's system
       Steals Alice's private key

Eve's attack:
  1. Has recorded encrypted traffic
  2. Has Alice's private key
  3. Decrypts ALL past messages ❌
  └─> COMPLETE COMPROMISE!


WITH FORWARD SECRECY (Labs 12 + 15):
═══════════════════════════════════════════════════════════════

DAY 1:
Alice ────encrypted messages────> Bob
  ^                                  ^
  │                                  │
Ephemeral keys              Ephemeral keys
(session_1)                 (session_1)
  │                                  │
  └──> DESTROYED after session <────┘

Eve records all traffic: ████████████████████

DAY 2:
Alice ────encrypted messages────> Bob
  ^                                  ^
  │                                  │
NEW Ephemeral keys          NEW Ephemeral keys
(session_2)                 (session_2)
  │                                  │
  └──> DESTROYED after session <────┘

DAY 7: Eve compromises Alice's system
       Steals Alice's credentials

Eve's attack:
  1. Has recorded encrypted traffic
  2. Has Alice's credentials
  3. Tries to decrypt past messages...
     └─> FAILS! ✓
         - Ephemeral keys destroyed
         - Session keys gone forever
         - Cannot recompute from long-term keys
  
  4. Can only decrypt NEW traffic (from Day 7 onward)
     └─> Past messages remain SECURE! ✓


KEY INSIGHT:
  Long-term key compromise ──> Only current session exposed
                           ┗━> Past sessions SECURE (keys destroyed)
                           ┗━> Future sessions SECURE (new ephemeral keys)
```

### 5. Complete Protocol Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              COMPLETE SECURE COMMUNICATION FLOW                  │
└─────────────────────────────────────────────────────────────────┘

PHASE 1: SESSION ESTABLISHMENT (Lab 12 + Lab 15)
═══════════════════════════════════════════════════════════════

Client                                              Server
  │                                                    │
  │ Generate ephemeral DH keys                        │
  │ ├─ private_key = random()                         │
  │ └─ public_key = g^private mod p                   │
  │                                                    │
  │ HANDSHAKE_INIT {public_key}                       │
  │ ──────────────────────────────────────────────────>│
  │                                                    │
  │                         Generate ephemeral DH keys │
  │                         ├─ private_key = random()  │
  │                         └─ public_key = g^priv     │
  │                                                    │
  │              HANDSHAKE_RESPONSE {public_key}      │
  │ <──────────────────────────────────────────────────│
  │                                                    │
  │ Compute shared secret & derive session_key        │
  │ ✓ Session established                             │
  ▼                                                    ▼
  
PHASE 2: SECURE MESSAGING (Lab 13)
═══════════════════════════════════════════════════════════════

  │ Prepare message: "Hello"                          │
  │ ├─ Generate nonce                                 │
  │ ├─ Prepare AAD (metadata)                         │
  │ ├─ Encrypt with AEAD                              │
  │ └─ Compute authentication tag                     │
  │                                                    │
  │ SECURE_MESSAGE {ciphertext, tag, nonce, AAD}      │
  │ ──────────────────────────────────────────────────>│
  │                                                    │
  │                              Decrypt with AEAD     │
  │                              ├─ Verify tag first!  │
  │                              ├─ If invalid: REJECT │
  │                              └─ Decrypt ciphertext │
  │                                                    │
  │              SECURE_MESSAGE {status: "ok"}        │
  │ <──────────────────────────────────────────────────│
  │                                                    │
  
PHASE 3: KEY ROTATION (Lab 14)
═══════════════════════════════════════════════════════════════

  │ ... after 1000 messages or 1 hour ...             │
  │                                                    │
  │ Detect rotation needed                            │
  │ ├─ Generate NEW ephemeral DH keys                 │
  │ └─ Destroy OLD ephemeral keys                     │
  │                                                    │
  │ KEY_ROTATION {new_public_key}                     │
  │ ──────────────────────────────────────────────────>│
  │                                                    │
  │                              Generate NEW keys     │
  │                              Destroy OLD keys      │
  │                                                    │
  │              KEY_ROTATION_RESP {new_public_key}   │
  │ <──────────────────────────────────────────────────│
  │                                                    │
  │ Compute NEW session_key                           │
  │ ✓ Rotation complete, continue messaging           │
  ▼                                                    ▼
  
PHASE 4: SESSION CLEANUP (Lab 15)
═══════════════════════════════════════════════════════════════

  │ User disconnects                                  │
  │                                                    │
  │ Destroy session:                                  │
  │ ├─ private_key = 0                                │
  │ ├─ public_key = 0                                 │
  │ ├─ session_key = b'\x00' * 32                     │
  │ └─ delete session object                          │
  │                                                    │
  │ ✓ FORWARD SECRECY ACHIEVED!                       │
  │   Past messages cannot be decrypted               │
  ▼                                                    ▼


SECURITY GUARANTEES:
═══════════════════════════════════════════════════════════════

┌────────────────────┬──────────────────────────────────────────┐
│ Confidentiality    │ ✓ Plaintext hidden (Lab 13 encryption)   │
├────────────────────┼──────────────────────────────────────────┤
│ Integrity          │ ✓ Tampering detected (Lab 13 auth tag)   │
├────────────────────┼──────────────────────────────────────────┤
│ Authentication     │ ✓ Sender verified (Lab 13 HMAC)          │
├────────────────────┼──────────────────────────────────────────┤
│ Forward Secrecy    │ ✓ Past secure (Lab 15 key destruction)   │
├────────────────────┼──────────────────────────────────────────┤
│ Key Freshness      │ ✓ Regular rotation (Lab 14)              │
├────────────────────┼──────────────────────────────────────────┤
│ Secure Key Exchange│ ✓ No pre-shared secrets (Lab 12 DH)      │
└────────────────────┴──────────────────────────────────────────┘
```

## 📊 Comparison Chart

```
┌─────────────────────────────────────────────────────────────────┐
│              SECURITY FEATURES COMPARISON                        │
└─────────────────────────────────────────────────────────────────┘

Feature                  Original System    Secure System (Labs 12-15)
─────────────────────────────────────────────────────────────────────
Key Exchange             ❌ Manual           ✅ Automatic DH (Lab 12)
Session Key              ❌ None             ✅ Derived from DH
Encryption               ⚠️  Caesar/Vigenère ✅ AEAD (Lab 13)
Authentication           ⚠️  Separate HMAC   ✅ Built into AEAD
Tampering Detection      ✅ SHA-256 hash     ✅ AEAD auth tag
Key Rotation             ❌ No               ✅ Automatic (Lab 14)
Forward Secrecy          ❌ No               ✅ Yes (Lab 15)
Ephemeral Keys           ❌ No               ✅ Per-session (Lab 15)
Message Counter          ❌ No               ✅ Replay protection
Session Management       ⚠️  Basic           ✅ Full lifecycle

THREAT PROTECTION:
─────────────────────────────────────────────────────────────────────
Eavesdropping           ⚠️  Weak cipher      ✅ Strong encryption
Man-in-the-Middle       ❌ Vulnerable        ✅ Protected (DH)
Message Tampering       ✅ Detected          ✅ Detected (AEAD)
Replay Attacks          ❌ Vulnerable        ✅ Protected (counter)
Key Compromise (future) ❌ All exposed       ✅ Only current session
Key Compromise (past)   ❌ All exposed       ✅ Past sessions safe
Long-term Storage       ❌ Risky             ✅ Safe (forward secrecy)
```

## 🎯 Real-World Protocol Mapping

```
┌─────────────────────────────────────────────────────────────────┐
│         OUR IMPLEMENTATION → REAL-WORLD PROTOCOLS                │
└─────────────────────────────────────────────────────────────────┘

Our Labs          →    Real Protocol          Used In
═══════════════════════════════════════════════════════════════════
Lab 12: DH            ECDHE (Elliptic Curve)   TLS 1.3, SSH
                      X25519                    Signal, WireGuard

Lab 13: AEAD          AES-GCM                   TLS 1.3, IPsec
                      ChaCha20-Poly1305         Signal, WireGuard

Lab 14: Key Mgmt      TLS Key Update            TLS 1.3
                      Double Ratchet            Signal, WhatsApp

Lab 15: Forward Sec   Ephemeral ECDHE           TLS 1.3 (mandatory)
                      DHE                        SSH

Complete Protocol:    TLS 1.3                   HTTPS
                      Signal Protocol            WhatsApp, Signal
                      Noise Protocol             WireGuard, Lightning
```

---

**This visual guide helps understand how all Labs 12-15 work together to provide comprehensive security!**
