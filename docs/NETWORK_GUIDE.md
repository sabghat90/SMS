# 🌐 Network Messaging Guide
## Multi-Terminal Secure Messaging System

---

## 🎯 Overview

The Secure Messaging System now supports **multi-terminal messaging**, allowing users to communicate with each other from separate terminals in real-time!

### Key Features
- ✅ **Client-Server Architecture** - Central server manages all users
- ✅ **Multi-User Support** - Multiple users can connect simultaneously
- ✅ **Real-Time Notifications** - Get notified when new messages arrive
- ✅ **Shared Blockchain** - All messages stored in centralized blockchain
- ✅ **Online Status** - See who's online
- ✅ **Thread-Safe** - Concurrent access properly managed

---

## 🚀 Quick Start Guide

### Step 1: Start the Server

Open **Terminal 1** and run:
```bash
python server.py
```

Expected output:
```
============================================================
               SECURE MESSAGING SERVER
============================================================

✓ Server started on 127.0.0.1:5555
✓ Waiting for connections...
✓ Press Ctrl+C to stop the server

  ✓ Demo user 'alice' registered
  ✓ Demo user 'bob' registered
  ✓ Demo user 'charlie' registered
```

**Keep this terminal open!** The server must run continuously.

---

### Step 2: Connect as Alice

Open **Terminal 2** and run:
```bash
python client.py
```

Then:
1. Choose **1** (Login)
2. Username: `alice`
3. Password: `alice123`

---

### Step 3: Connect as Bob

Open **Terminal 3** and run:
```bash
python client.py
```

Then:
1. Choose **1** (Login)
2. Username: `bob`
3. Password: `bob123`

---

### Step 4: Send a Message!

In **Alice's terminal (Terminal 2)**:
1. Choose **1** (Send Message)
2. Receiver: `bob`
3. Message: `Hello Bob! This is Alice.`
4. Encryption: **1** (Caesar Cipher)
5. Shift: `5`

---

### Step 5: Check Messages

In **Bob's terminal (Terminal 3)**:
- You should see a notification: `🔔 New message from alice!`
- Choose **2** (View Messages)
- Choose **y** to decrypt
- Enter shift: `5`
- See the decrypted message!

---

## 📋 Complete Usage Instructions

### Server Operations

#### Starting the Server
```bash
python server.py
```

The server will:
- Start on port 5555
- Create demo users (alice, bob, charlie)
- Generate ElGamal keys for each user
- Initialize the blockchain
- Wait for client connections

#### Stopping the Server
Press `Ctrl+C` in the server terminal

The server will:
- Disconnect all clients gracefully
- Save blockchain state (in memory)
- Close all sockets

#### Server Features
- ✅ Multi-threaded (handles multiple clients)
- ✅ Thread-safe operations (locks for shared data)
- ✅ Real-time message delivery
- ✅ Automatic key management
- ✅ Centralized blockchain

---

### Client Operations

#### 1. Login
```
Choice: 1 (Login)
Username: alice
Password: alice123
```

#### 2. Register New User
```
Choice: 2 (Register)
Username: david
Password: david123
Email: david@example.com
```

The system will:
- Create user account
- Generate ElGamal keys
- Register public key with KDC
- Display key information

#### 3. Send Message

**Step-by-Step:**
```
Menu > 1 (Send Message)

Available users:
  - bob (🟢 online)
  - charlie (⚫ offline)

Receiver: bob
Message: Secret meeting at 3pm

--- SELECT ENCRYPTION ---
1. Caesar Cipher
2. Vigenère Cipher
3. XOR Stream Cipher
4. Mini Block Cipher

Choice: 2 (Vigenère)
Key: SECRET

✓ Message sent successfully!
  Block #2
  Block hash: 00a1b2c3...
  Message hash: 9b871c6d...
```

#### 4. View Messages
```
Menu > 2 (View Messages)

Found 2 message(s):

------------------------------------------------------------
Message #1 (Block #1)
From: bob
To: alice
Timestamp: 2025-10-31 15:30:45
Encryption: Caesar
Ciphertext: Mjqqt Fqnhj...

Decrypt this message? (y/n): y

[Decrypting with Caesar]
Enter shift value used: 5

✓ Decrypted message: Hello Alice

[Verifying message integrity...]
✓ Message integrity verified! Hash matches.
```

#### 5. View Blockchain
```
Menu > 3 (View Blockchain)

Total blocks: 3

============================================================
Block #0
Timestamp: 2025-10-31 14:00:00
Previous Hash: 0
Block Hash: 00123abc...
Nonce: 142

============================================================
Block #1
Timestamp: 2025-10-31 15:30:45
Previous Hash: 00123abc...
Block Hash: 00456def...
Nonce: 891

Message Data:
  Sender: bob
  Receiver: alice
  Method: Caesar
```

#### 6. Verify Blockchain
```
Menu > 4 (Verify Blockchain)

✓ Blockchain is valid
  All 3 blocks verified
  Chain integrity: INTACT
```

---

## 🔧 Configuration

### Server Configuration

Edit `server.py`:
```python
# Change server address and port
server = MessageServer(host='0.0.0.0', port=5555)

# Change blockchain difficulty
self.blockchain = MessageBlockchain(difficulty=3)

# Add more demo users
demo_users = [
    ("alice", "alice123", "alice@example.com"),
    ("bob", "bob123", "bob@example.com"),
    ("charlie", "charlie123", "charlie@example.com"),
    ("david", "david123", "david@example.com"),  # Add new user
]
```

### Client Configuration

Edit `client.py`:
```python
# Connect to different server
client = MessageClient(host='192.168.1.100', port=5555)

# Adjust timeout
response = self._receive_response(timeout=10)
```

---

## 🌐 Network Architecture

### System Diagram

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Terminal 1 │         │  Terminal 2 │         │  Terminal 3 │
│             │         │             │         │             │
│   SERVER    │         │   Alice     │         │    Bob      │
│  (server.py)│         │ (client.py) │         │ (client.py) │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │    ◄─── TCP/IP ───────┤                       │
       │                       │                       │
       │    ◄─── TCP/IP ───────────────────────────────┤
       │                       │                       │
       │                       │                       │
   ┌───▼────────────────────────────────────────────────┐
   │         SHARED BLOCKCHAIN                          │
   │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐              │
   │  │  0  │─►│  1  │─►│  2  │─►│  3  │─►...         │
   │  └─────┘  └─────┘  └─────┘  └─────┘              │
   └────────────────────────────────────────────────────┘
```

### Communication Flow

```
Client (Alice)                Server                 Client (Bob)
     │                           │                         │
     ├──── LOGIN ───────────────►│                         │
     │                           │                         │
     │◄─── SUCCESS ──────────────┤                         │
     │                           │                         │
     │                           │◄──── LOGIN ─────────────┤
     │                           │                         │
     │                           ├──── SUCCESS ───────────►│
     │                           │                         │
     ├──── SEND_MESSAGE ────────►│                         │
     │     (to Bob)              │                         │
     │                           ├── Store in Blockchain   │
     │                           │                         │
     │◄─── SUCCESS ──────────────┤                         │
     │                           │                         │
     │                           ├──── NOTIFICATION ──────►│
     │                           │     (New msg from Alice)│
     │                           │                         │
     │                           │◄─── GET_MESSAGES ───────┤
     │                           │                         │
     │                           ├──── MESSAGES ──────────►│
     │                           │                         │
```

### Protocol Messages

**LOGIN Request:**
```json
{
  "command": "LOGIN",
  "username": "alice",
  "password": "alice123"
}
```

**LOGIN Response:**
```json
{
  "status": "success",
  "message": "Login successful",
  "session_id": "abc123def456",
  "username": "alice"
}
```

**SEND_MESSAGE Request:**
```json
{
  "command": "SEND_MESSAGE",
  "sender": "alice",
  "receiver": "bob",
  "plaintext": "Hello Bob",
  "encryption_method": "Caesar",
  "encryption_params": {"shift": 3}
}
```

**SEND_MESSAGE Response:**
```json
{
  "status": "success",
  "message": "Message sent successfully",
  "block_index": 2,
  "block_hash": "00a1b2c3...",
  "message_hash": "9b871c...",
  "encryption_params": {"shift": 3}
}
```

**NEW_MESSAGE Notification:**
```json
{
  "type": "NEW_MESSAGE",
  "from": "alice",
  "timestamp": "2025-10-31 15:30:45"
}
```

---

## 💡 Usage Scenarios

### Scenario 1: Two Users Chatting

**Terminal 1:** Server
```bash
python server.py
```

**Terminal 2:** Alice
```bash
python client.py
# Login as alice
# Send message to bob with Caesar cipher
```

**Terminal 3:** Bob
```bash
python client.py
# Login as bob
# Receive notification
# View and decrypt message
# Reply to alice
```

---

### Scenario 2: Three Users Group

**Terminal 1:** Server
```bash
python server.py
```

**Terminal 2:** Alice
```bash
python client.py
# Alice sends to Bob
# Alice sends to Charlie
```

**Terminal 3:** Bob
```bash
python client.py
# Bob reads messages
# Bob sends to Alice
```

**Terminal 4:** Charlie
```bash
python client.py
# Charlie reads messages
# Charlie sends to both
```

---

### Scenario 3: Testing Different Ciphers

**Alice** sends 4 messages to **Bob**, each with different cipher:

1. **Message 1:** Caesar (shift=5)
2. **Message 2:** Vigenère (key="SECRET")
3. **Message 3:** XOR Stream (random key)
4. **Message 4:** Block Cipher (random key)

**Bob** decrypts each one with the appropriate key.

---

## 🧪 Testing Multi-Terminal Features

### Test 1: Real-Time Notification

1. Start server
2. Login Alice (Terminal 2)
3. Login Bob (Terminal 3)
4. Alice sends message to Bob
5. **Verify:** Bob sees instant notification in Terminal 3

### Test 2: Online Status

1. Start server
2. Login Alice
3. Alice checks user list
4. **Verify:** All users shown, online status indicated
5. Login Bob
6. Alice checks user list again
7. **Verify:** Bob now shows as online

### Test 3: Concurrent Messaging

1. Start server
2. Login Alice, Bob, Charlie
3. Alice sends to Bob (simultaneously)
4. Bob sends to Charlie (simultaneously)
5. Charlie sends to Alice (simultaneously)
6. **Verify:** All messages delivered correctly
7. **Verify:** Blockchain contains all 3 messages

### Test 4: Blockchain Consistency

1. Start server
2. Multiple clients send messages
3. Each client verifies blockchain
4. **Verify:** All clients see same blockchain
5. **Verify:** All validations pass

### Test 5: Disconnection Handling

1. Start server
2. Login Alice and Bob
3. Bob sends message to Alice
4. Close Bob's terminal (force disconnect)
5. Alice checks user list
6. **Verify:** Bob shows as offline
7. Alice sends message to Bob (offline)
8. **Verify:** Message stored in blockchain
9. Bob reconnects
10. **Verify:** Bob can retrieve the message

---

## 🔒 Security Considerations

### Network Security
- **Local Network Only:** Default configuration uses localhost (127.0.0.1)
- **No Encryption:** Socket communication is not encrypted (plaintext JSON)
- **No Authentication:** Simple username/password (not production-ready)

### For Production Use (Educational Note)
Would need:
- ✅ TLS/SSL for socket encryption
- ✅ Token-based authentication (JWT)
- ✅ Rate limiting
- ✅ Input validation and sanitization
- ✅ Database persistence
- ✅ Message queue for reliability
- ✅ Load balancing for scalability

---

## ⚠️ Troubleshooting

### Problem: "Could not connect to server"
**Solution:**
- Ensure server is running: `python server.py`
- Check if port 5555 is available
- Verify firewall settings
- Check host/port in client.py

### Problem: "Server timeout"
**Solution:**
- Server might be busy
- Increase timeout in client
- Check server terminal for errors
- Restart server

### Problem: "User already logged in"
**Solution:**
- User can only login from one terminal
- Logout from other terminal first
- Or use different username

### Problem: Notification not received
**Solution:**
- Ensure receiver is logged in
- Check notification thread is running
- Server must be running
- Check for network issues

### Problem: Messages not appearing
**Solution:**
- Use "View Messages" to refresh
- Check if message was sent successfully
- Verify blockchain contains the message
- Check sender/receiver usernames

---

## 📊 Performance Considerations

### Server Capacity
- **Max Clients:** Limited by system resources (typically 100+)
- **Message Throughput:** ~100 messages/second
- **Blockchain Size:** Grows with messages (no pruning)
- **Memory Usage:** Increases with connected clients

### Network Requirements
- **Bandwidth:** Minimal (text-based messages)
- **Latency:** Local network ~1-5ms
- **Packet Size:** ~1-4 KB per message

---

## 🎓 Educational Notes

### Concepts Demonstrated

**Networking:**
- Socket programming (TCP/IP)
- Client-server architecture
- Multi-threading
- Concurrent access control

**Distributed Systems:**
- Shared state management
- Synchronization (locks)
- Real-time notifications
- Consistency guarantees

**Security:**
- End-to-end encryption concept
- Centralized key distribution
- Blockchain immutability
- Message integrity verification

---

## 🚀 Advanced Features (Optional Enhancements)

### 1. Group Messaging
Extend protocol to support broadcast messages to multiple recipients.

### 2. File Transfer
Add support for sending encrypted files.

### 3. Message History
Store messages in database for persistence across server restarts.

### 4. Web Interface
Create web-based client using Flask/WebSocket.

### 5. End-to-End Encryption
Use ElGamal to encrypt messages directly between users.

---

## ✅ Checklist

### Server Setup
- [ ] Server running on Terminal 1
- [ ] Demo users registered
- [ ] Blockchain initialized
- [ ] Server listening on port 5555

### Client Setup (per user)
- [ ] Client connected to server
- [ ] User logged in successfully
- [ ] Notification listener running
- [ ] Ready to send/receive messages

### Testing
- [ ] Send message between terminals
- [ ] Receive real-time notification
- [ ] Decrypt message successfully
- [ ] Verify message integrity
- [ ] View blockchain from multiple clients
- [ ] Verify blockchain consistency

---

## 📞 Quick Reference

### Start Server
```bash
python server.py
```

### Start Client
```bash
python client.py
```

### Demo Credentials
```
alice / alice123
bob / bob123
charlie / charlie123
```

### Default Server Address
```
Host: 127.0.0.1
Port: 5555
```

---

**Version:** 1.0 (Network-Enabled)  
**Last Updated:** October 31, 2025  
**Status:** Ready for Multi-Terminal Use! 🚀
