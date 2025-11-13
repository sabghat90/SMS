# Network Messaging Guide
## Multi-Terminal Secure Messaging System

---

## Overview

The Secure Messaging System supports **multi-terminal messaging**, allowing users to communicate with each other from separate terminals in real-time!

### Key Features
- **Client-Server Architecture** - Central server manages all users
- **Multi-User Support** - Multiple users can connect simultaneously
- **Real-Time Notifications** - Get notified when new messages arrive
- **Shared Blockchain** - All messages stored in centralized blockchain
- **Online Status** - See who's online
- **Thread-Safe** - Concurrent access properly managed

---

## Quick Start Guide

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

Server started on 127.0.0.1:5555
Waiting for connections...
Press Ctrl+C to stop the server

Setting up demo users...
Demo user 'alice' registered
Demo user 'bob' registered
Demo user 'charlie' registered
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
- You should see a notification: `New message from alice!`
- Choose **2** (View Messages)
- Choose **y** to decrypt
- Enter shift: `5`
- See the decrypted message!

---

## Complete Usage Instructions

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
- Save blockchain state
- Close all sockets

#### Server Features
- Multi-threaded (handles multiple clients)
- Thread-safe operations (locks for shared data)
- Real-time message delivery
- Automatic key management
- Centralized blockchain

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
  - bob (+ online)
  - charlie (X offline)

Receiver: bob
Message: Secret meeting at 3pm

--- SELECT ENCRYPTION ---
1. Caesar Cipher
2. Vigenère Cipher
3. XOR Stream Cipher
4. Mini Block Cipher

Choice: 2 (Vigenère)
Key: SECRET

Message sent successfully!
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

Decrypted message: Hello Alice!

[Verifying message integrity...]
Message integrity verified! Hash matches.
------------------------------------------------------------
```

#### 5. View All Users
```
Menu > 3 (Get Users)

Registered Users:
  - alice (+ online)
  - bob (+ online)
  - charlie (X offline)
```

#### 6. Verify Blockchain
```
Menu > 4 (Verify Blockchain)

[Verifying blockchain integrity...]
- Checking all block hashes...
- Verifying previous hash links...
- Checking proof of work...

Blockchain is valid!
  Total blocks: 5
  All hashes verified
  Chain integrity confirmed
```

#### 7. View Blockchain
```
Menu > 5 (View Blockchain)

--- BLOCKCHAIN EXPLORER ---

Block #0 (Genesis Block)
Hash: 000abc123...
Previous: None
Timestamp: 2025-10-31 14:00:00

Block #1
Hash: 001def456...
Previous: 000abc123...
From: alice → bob
Encryption: Caesar
Timestamp: 2025-10-31 14:15:23

[... more blocks ...]
```

---

## Network Architecture

### System Components

1. **Server (`server.py`)**
   - Multi-threaded TCP server
   - Manages user authentication
   - Stores centralized blockchain
   - Handles message routing
   - Manages ElGamal Key Distribution Center (KDC)

2. **Client (`client.py`)**
   - Connects to server via TCP
   - Interactive menu interface
   - Background notification listener
   - Local encryption/decryption

3. **Communication Protocol**
   - JSON-based request/response
   - Commands: LOGIN, REGISTER, SEND_MESSAGE, GET_MESSAGES, etc.
   - Thread-safe socket operations

### Data Flow

```
Client A                    Server                      Client B
   │                           │                            │
   │─── LOGIN ──────────────►  │                            │
   │◄── SUCCESS + SESSION ────  │                            │
   │                           │                            │
   │─── SEND_MESSAGE ────────►  │                            │
   │  (encrypted locally)       │                            │
   │                           │                            │
   │                           │ [Add to Blockchain]         │
   │                           │ [Mine Block - PoW]          │
   │                           │                            │
   │◄── MESSAGE_SENT ─────────  │                            │
   │                           │                            │
   │                           │ ─── NOTIFICATION ────────► │
   │                           │                            │
   │                           │ ◄── GET_MESSAGES ───────── │
   │                           │                            │
   │                           │ ─── MESSAGES ────────────► │
   │                           │                            │
```

---

## Advanced Features

### ElGamal Public Key Cryptography

Each user has:
- **Private Key**: Kept secret, used for decryption
- **Public Key**: Shared via KDC, used by others for encryption

**Sending ElGamal Message:**
```
Menu > 1 (Send Message)
Receiver: bob
Message: Top secret information
Encryption: 5 (ElGamal)

[System retrieves bob's public key from KDC]
[Encrypts message using bob's public key]

Message sent!
Note: Only bob can decrypt this with his private key
```

**Receiving ElGamal Message:**
```
Menu > 2 (View Messages)
Decrypt: y

[System uses your private key to decrypt]
Decrypted: Top secret information
```

### Key Distribution Center (KDC)

The server acts as a KDC:
- Stores all public keys
- Provides public keys on request
- Automatically manages keys for registered users

### Real-Time Notifications

When a client is logged in:
- Background thread listens for server notifications
- Alerts user when new messages arrive
- Non-intrusive (doesn't interrupt current operation)

Example notification:
```
> (You're typing...)

New message from alice!
Type '2' to view messages

> 
```

---

## Demo Users

The server creates three demo users automatically:

| Username | Password | Purpose |
|----------|----------|---------|
| alice | alice123 | Demo user A |
| bob | bob123 | Demo user B |
| charlie | charlie123 | Demo user C |

You can also register new users via the client.

---

## Security Features

### Network Security
- **Authentication Required**: Must login before operations
- **Session Management**: Server tracks active sessions
- **Encrypted Credentials**: Passwords hashed with SHA-256

### Message Security
- **Client-Side Encryption**: Messages encrypted before sending
- **Multiple Cipher Options**: Choose encryption method
- **Hash Verification**: SHA-256 ensures message integrity
- **Blockchain Ledger**: Immutable message history

### Storage Security
- **Encrypted User Data**: XOR + HMAC protection
- **Encrypted Keys**: ElGamal keys stored securely
- **HMAC Integrity**: Tamper detection for all data

---

## Troubleshooting

### Problem: "Could not connect to server"
**Solution:**
1. Ensure server is running: `python server.py`
2. Check port 5555 is not blocked by firewall
3. Verify both on same network (or localhost)

### Problem: "Login failed"
**Solution:**
1. Check username/password spelling
2. Use demo users: alice/alice123, bob/bob123
3. Or register new user first

### Problem: "No messages found"
**Solution:**
- Have another user send you a message first
- Check you're logged in as the correct user

### Problem: Decryption fails
**Solution:**
- Ensure you're using the correct encryption method
- Use the exact same key that was used for encryption
- For ElGamal, only the intended recipient can decrypt

### Problem: Server crashes
**Solution:**
1. Check error message in server terminal
2. Ensure data directory has write permissions
3. Restart server: `python server.py`

---

## Network Modes

### 1. Local Network (Default)
```bash
# Server
python server.py
# Listens on 127.0.0.1:5555

# Client (same machine)
python client.py
# Connects to 127.0.0.1:5555
```

### 2. LAN Network (Multiple Computers)

**On Server Computer:**
```bash
# Find your IP address
ipconfig  # Windows
ifconfig  # Linux/Mac

# Edit server.py if needed:
# host = '0.0.0.0'  # Listen on all interfaces
# port = 5555

python server.py
```

**On Client Computers:**
```bash
# Edit client.py:
# host = '192.168.1.100'  # Server's IP address
# port = 5555

python client.py
```

**Note:** Ensure firewall allows port 5555

---

## Command Reference

### Server Commands
- `python server.py` - Start server
- `Ctrl+C` - Stop server gracefully

### Client Menu Options

**Not Logged In:**
1. Login
2. Register
3. Exit

**Logged In:**
1. Send Message
2. View Messages
3. Get Users
4. Verify Blockchain
5. View Blockchain
6. Logout
7. Exit

---

## Performance Notes

- **Concurrent Users**: Tested with 10+ simultaneous clients
- **Message Throughput**: Hundreds of messages per minute
- **Blockchain Mining**: ~0.1-1 second per block (difficulty=2)
- **Encryption Speed**: Near-instant for short messages

---

## Best Practices

1. **Always Start Server First**
   - Clients can't connect without running server

2. **Keep Server Running**
   - Server terminal must stay open for messaging

3. **Use Different Terminals**
   - One server terminal + multiple client terminals

4. **Save Encryption Keys**
   - Copy and save keys for modern ciphers (XOR, Block)

5. **Verify Blockchain Regularly**
   - Ensures message integrity

6. **Logout Before Closing**
   - Clean session termination

---

## Learning Objectives

After using network mode, you should understand:

- **Client-Server Architecture**: How distributed systems communicate
- **Network Protocols**: JSON-based request/response patterns
- **Multi-Threading**: Concurrent client handling
- **Session Management**: Authentication and active sessions
- **Public Key Infrastructure**: KDC and key distribution
- **Real-Time Systems**: Notification mechanisms
- **Distributed Ledgers**: Shared blockchain across clients

---

## Example Multi-User Scenario

**Scenario: Three-Way Communication**

1. **Start Server**
   ```bash
   Terminal 1> python server.py
   ```

2. **Alice Joins**
   ```bash
   Terminal 2> python client.py
   Login: alice / alice123
   ```

3. **Bob Joins**
   ```bash
   Terminal 3> python client.py
   Login: bob / bob123
   ```

4. **Charlie Joins**
   ```bash
   Terminal 4> python client.py
   Login: charlie / charlie123
   ```

5. **Alice → Bob** (Caesar, shift=3)
   ```
   Terminal 2> Send Message to bob: "Meeting at noon"
   ```

6. **Bob Receives & Responds**
   ```
   Terminal 3> View Messages
   Terminal 3> Send Message to alice: "Confirmed!"
   ```

7. **Charlie Sends Broadcast**
   ```
   Terminal 4> Send to alice: "Project update"
   Terminal 4> Send to bob: "Project update"
   ```

8. **All Verify Blockchain**
   ```
   All terminals> Verify Blockchain
   Result: Chain valid, 5 blocks
   ```

---

## Next Steps

- **Try Different Ciphers**: Experiment with all 5 encryption methods
- **Test ElGamal**: Use public key cryptography
- **Verify Integrity**: Check blockchain after each message
- **Scale Up**: Connect 5+ clients simultaneously
- **Security Testing**: Try tampering with data files

---

**Ready for Multi-User?**
```bash
# Terminal 1
python server.py

# Terminal 2+
python client.py
```

**Enjoy secure multi-terminal messaging!**
