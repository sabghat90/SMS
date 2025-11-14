# 🚀 Quick Test Guide - Verify All Fixes

## Automated Test (Run First)
```powershell
python test_fixes.py
```

**Expected Output**:
```
✓ PASSED: Blockchain Validation
✓ PASSED: Blockchain Performance
✓ ALL TESTS PASSED
```

---

## Manual Test - Classical Mode Online Status

### Terminal 1 - Server
```powershell
python server.py
```

### Terminal 2 - Alice (Classical Mode)
```powershell
python client.py
```
```
Use secure mode with Labs 12-15? (y/n, default=y): n
```
```
> 1  # Login
Username: alice
Password: alice123
```

### Terminal 3 - Bob (Classical Mode)
```powershell
python client.py
```
```
Use secure mode with Labs 12-15? (y/n, default=y): n
```
```
> 1  # Login
Username: bob
Password: bob123
```

### Back to Terminal 2 (Alice)
```
> 4  # View users
```

### ✅ Expected Result:
```
--- AVAILABLE USERS ---
• bob [ONLINE]    ← Should show ONLINE!
• charlie
```

---

## Manual Test - Blockchain Verification

### From Alice's Terminal
```
> 3  # Send message
Receiver: bob
Message: Test message
Choice (1-4): 1  # Caesar
Shift value (default 3): 3
```

```
> 6  # Verify blockchain
```

### ✅ Expected Result:
```
--- BLOCKCHAIN VERIFICATION ---
✓ Blockchain is VALID
Message: Blockchain is valid (2 blocks)
Chain length: 2 blocks
```

---

## Manual Test - No Timeouts

### From Alice's Terminal (Send 5 Messages Rapidly)
```
> 3
Receiver: bob
Message: Message 1
Choice: 1, Shift: 3

> 3
Receiver: bob
Message: Message 2
Choice: 2, Key: SECRET

> 3
Receiver: bob
Message: Message 3
Choice: 3

> 3
Receiver: bob
Message: Message 4
Choice: 4

> 3
Receiver: bob
Message: Message 5
Choice: 1, Shift: 5
```

### ✅ Expected Result:
- All 5 messages sent successfully ✓
- No timeout errors ✓
- Server console shows all 5 blocks added ✓

```
> 6  # Verify blockchain
```
```
✓ Blockchain is VALID
Message: Blockchain is valid (6 blocks)
```

---

## All Tests Pass Checklist

- [✓] `test_fixes.py` shows all passed
- [✓] Classical mode users show as [ONLINE]
- [✓] Blockchain verification returns VALID
- [✓] No timeouts when sending messages
- [✓] Rapid messages all succeed
- [✓] Server console shows no errors
- [✓] Both classical and secure modes work

---

## If Issues Occur

### Issue: Users still not showing online
**Check**: Make sure both clients chose 'n' for classical mode
**Fix**: Restart both clients and answer 'n' when prompted

### Issue: Blockchain still invalid
**Check**: Run `python test_fixes.py` to verify blockchain code
**Fix**: Make sure you're using the latest server.py and blockchain.py

### Issue: Still getting timeouts
**Check**: Server console for actual error messages
**Fix**: Ensure server.py has `client_socket.settimeout(30.0)` on line ~143

### Issue: Can't connect
**Check**: Is server running?
**Fix**: Start server first in Terminal 1

---

## Success Indicators

### Server Console Should Show:
```
[12:34:56] alice logged in
[12:34:57] bob logged in
[12:35:10] Message: alice -> bob (Block #1)
[12:35:15] Message: alice -> bob (Block #2)
[12:35:20] Message: alice -> bob (Block #3)
```

### Client Console Should Show:
```
✓ Message sent successfully!
Block #1
Block hash: abc123...

[Logged in as: alice]
```

### No Error Messages Should Appear:
- ❌ "Server timeout"
- ❌ "Client timed out"
- ❌ "Blockchain is invalid"
- ❌ "Connection lost"

---

## Quick Comparison Test

### Test Both Modes:

#### Classical Mode (choose 'n'):
```
✓ Login works
✓ Shows as ONLINE
✓ Can send messages (Caesar, Vigenere, XOR, Block)
✓ No timeouts
✓ Blockchain verification works
```

#### Secure Mode (choose 'y' or just press Enter):
```
✓ DH handshake completes
✓ Shows as ONLINE
✓ Can send messages (AEAD encrypted)
✓ No timeouts
✓ Blockchain verification works
✓ Key rotation works
```

---

## Performance Check

Run this from Python:
```python
import time
from src.core.blockchain import MessageBlockchain
from src.core.storage import SecureStorage

storage = SecureStorage(data_dir="data")
blockchain = MessageBlockchain(difficulty=2, storage=storage)

start = time.time()
for i in range(10):
    blockchain.add_message_block(
        sender="alice", receiver="bob",
        ciphertext=f"msg_{i}", message_hash=f"hash_{i}",
        encryption_method="Caesar"
    )
elapsed = time.time() - start
print(f"10 blocks in {elapsed:.2f}s")
# Should be under 1 second!
```

---

## 🎉 All Fixes Verified!

If all tests pass, your SMS system is ready for:
- ✅ Classroom demonstrations
- ✅ Student testing
- ✅ Lab assignments
- ✅ Production use

**Both classical and secure modes work perfectly!**
