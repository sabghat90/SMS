# Quick Start Guide
## Secure Messaging System

### 🚀 Run the Application

```bash
python main.py
```

### 📝 Quick Demo Steps

#### 1. Login with Demo Account
```
Choice: 2 (Login)
Username: alice
Password: alice123
```

#### 2. Send a Test Message
```
Choice: 1 (Send Encrypted Message)
Receiver: bob
Message: Hello Bob! This is a secret message.
Encryption Method: 2 (Vigenère Cipher)
Key: SECRET
```

#### 3. Login as Bob
```
Choice: 5 (Logout)
Choice: 2 (Login)
Username: bob
Password: bob123
```

#### 4. View and Decrypt Message
```
Choice: 2 (View My Messages)
Decrypt: y (yes)
Key: SECRET
```

#### 5. Verify Blockchain
```
Choice: 4 (Verify Blockchain Integrity)
```

---

## 🎮 Menu Options Explained

### Main Menu (Not Logged In)
1. **Register** - Create new user account
2. **Login** - Access your account
3. **Exit** - Close application

### Main Menu (Logged In)
1. **Send Encrypted Message** - Encrypt and send message
2. **View My Messages** - See your message history
3. **View Blockchain** - Explore all blocks
4. **Verify Blockchain Integrity** - Check chain validity
5. **Logout** - End session
6. **Exit** - Close application

---

## 🔐 Encryption Methods Guide

### Caesar Cipher
- **Type:** Classical substitution cipher
- **Parameter:** Shift value (e.g., 3)
- **Best for:** Simple alphabetic messages
- **Example:** Shift=3, "ABC" → "DEF"

### Vigenère Cipher
- **Type:** Polyalphabetic cipher
- **Parameter:** Keyword (e.g., "SECRET")
- **Best for:** Text messages with variable security
- **Example:** Key="KEY", "HELLO" → "RIJVS"

### XOR Stream Cipher
- **Type:** Modern stream cipher
- **Parameter:** Key (hex) or random generation
- **Best for:** Any text or binary data
- **Note:** Save the key (hex) for decryption

### Mini Block Cipher
- **Type:** Modern block cipher
- **Parameter:** 8-byte key (hex) or random
- **Best for:** Fixed-size data blocks
- **Note:** Save the key (hex) for decryption

---

## 💡 Tips

### For Encryption
- **Classical ciphers:** Easy to use, remember the key!
- **Modern ciphers:** Copy the key (hex) displayed after encryption
- **Always note which method you used**

### For Decryption
- Must use the **same encryption method**
- Must provide the **exact same key**
- Hash verification shows if message was tampered

### For Security
- Use strong passwords (6+ characters)
- Don't share your private keys
- Verify blockchain regularly
- Check hash integrity after decryption

---

## 🧪 Test Scenarios

### Scenario 1: Basic Communication
1. Alice sends Caesar cipher message to Bob (shift=5)
2. Bob receives and decrypts with shift=5
3. Verify hash matches

### Scenario 2: Advanced Encryption
1. Alice sends XOR stream cipher message
2. Note the key displayed (hex format)
3. Bob decrypts using the key
4. Check integrity verification

### Scenario 3: Blockchain Integrity
1. Send multiple messages
2. View blockchain
3. Verify integrity
4. All checks should pass ✓

---

## ❓ Common Questions

**Q: What if I forget my encryption key?**  
A: Message cannot be decrypted. Keys are not stored in the system.

**Q: Can I send messages to myself?**  
A: No, the system prevents self-messaging for demonstration purposes.

**Q: What happens if I enter wrong decryption key?**  
A: Decryption will fail or produce garbage. Hash verification will fail.

**Q: Can I view others' messages?**  
A: You can see encrypted messages in blockchain, but can't decrypt without keys.

**Q: Is the blockchain truly immutable?**  
A: Yes, any tampering will be detected by integrity verification.

---

## 📊 Understanding the Output

### After Sending Message:
```
[Step 1] Computing SHA-256 hash of message...
✓ Message hash: 9b871c6d...

[Step 2] Encrypting with Vigenère Cipher...
✓ Message encrypted
  Ciphertext preview: IQNNT...

[Step 3] Adding to blockchain...
✓ Block #2 created and mined
  Block hash: 0012a5b8c...
  Timestamp: 2025-10-31 14:23:45
```

### After Decrypting:
```
✓ Decrypted message: Hello Bob!

[Verifying message integrity...]
✓ Message integrity verified! Hash matches.
```

---

## 🎯 Learning Checkpoints

After completing this quick start, you should understand:
- ✅ User authentication flow
- ✅ Encryption method selection
- ✅ Message integrity verification
- ✅ Blockchain immutability
- ✅ Key management importance

---

**Ready to Start?** Run: `python main.py`
