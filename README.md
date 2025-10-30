# 🔐 Secure Messaging System
## Information Security Labs 01-11 - Case Study

A comprehensive secure messaging application integrating all Information Security lab concepts into a working multi-user system with network support.

---

## 📁 Project Structure

```
SMS/
├── src/
│   ├── core/              # Core cryptography modules
│   │   ├── crypto_math.py        # Math primitives (Lab 01-02)
│   │   ├── authentication.py     # User auth (Lab 01-02)
│   │   ├── classical_ciphers.py  # Caesar, Vigenère (Lab 03-04)
│   │   ├── modern_ciphers.py     # XOR, Block cipher (Lab 05)
│   │   ├── hashing.py            # SHA-256 (Lab 06)
│   │   ├── blockchain.py         # Blockchain, PoW (Lab 07)
│   │   └── elgamal.py            # ElGamal, KDC (Lab 09, 11)
│   │
│   └── network/           # Network modules
│       ├── server.py      # Multi-user server
│       └── client.py      # Network client
│
├── docs/                  # Documentation
│   ├── QUICKSTART.md
│   ├── ARCHITECTURE.md
│   ├── NETWORK_GUIDE.md
│   ├── DEMO_GUIDE.md
│   ├── TESTING.md
│   └── LAB_MAPPING.md
│
├── main.py                # Standalone application
├── run_server.py          # Server launcher
├── run_client.py          # Client launcher
└── run_standalone.py      # Standalone launcher
```

---

## 🚀 Quick Start

### Network Mode (Multi-User)

```bash
# Terminal 1 - Start Server
python run_server.py

# Terminal 2 - Client (Alice)
python run_client.py

# Terminal 3 - Client (Bob)
python run_client.py
```

**Demo Users:** alice/alice123, bob/bob123, charlie/charlie123

### Standalone Mode (Single User)

```bash
python run_standalone.py
```

---

## 📚 Features

### Security
- ✅ User Authentication (registration/login)
- ✅ 4 Encryption Methods (Caesar, Vigenère, XOR, Block)
- ✅ Message Integrity (SHA-256 hashing)
- ✅ Blockchain (Immutable logging with PoW)
- ✅ Public Key Crypto (ElGamal)
- ✅ Key Distribution (KDC)

### Network
- ✅ Multi-User (concurrent connections)
- ✅ Real-Time (instant notifications)
- ✅ Thread-Safe (proper synchronization)
- ✅ TCP/IP (client-server architecture)

---

## 📖 Documentation

- **[QUICKSTART.md](docs/QUICKSTART.md)** - 5-minute setup guide
- **[NETWORK_GUIDE.md](docs/NETWORK_GUIDE.md)** - Multi-terminal usage
- **[DEMO_GUIDE.md](docs/DEMO_GUIDE.md)** - Presentation script
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design
- **[TESTING.md](docs/TESTING.md)** - Testing procedures
- **[LAB_MAPPING.md](docs/LAB_MAPPING.md)** - Lab integration

---

## 🎓 Lab Integration

| Lab | Topic | Implementation |
|-----|-------|----------------|
| 01-02 | Python, Dictionaries | User auth, data storage |
| 03 | Caesar Cipher | Classical encryption |
| 04 | Vigenère Cipher | Polyalphabetic cipher |
| 05 | Modern Ciphers | XOR & Block cipher |
| 06 | Hashing | SHA-256 integrity |
| 07 | Blockchain | PoW, immutable ledger |
| 09 | ElGamal | Public key encryption |
| 11 | Key Distribution | Centralized KDC |

---

## 🔧 Development

### Requirements
- Python 3.7+
- No external dependencies (stdlib only)

### Import Structure
```python
from src.core import UserAuthentication, MessageBlockchain
from src.network import MessageServer, MessageClient
```

---

**Ready to start?** Run `python run_server.py` and `python run_client.py` in separate terminals!
