# Secure Data Storage

## Overview

The Secure Messaging System now includes encrypted persistent storage for user data and temporary blockchain storage.

## Features

### 1. **Encrypted User Data Storage**
- User credentials (hashed passwords) stored in encrypted JSON files
- Uses Fernet (symmetric encryption based on AES-128)
- Automatic encryption/decryption on save/load
- Protected by a unique encryption key

### 2. **Encrypted User Keys Storage**
- ElGamal key pairs stored securely
- Encrypted using the same Fernet cipher
- Keys persist across sessions

### 3. **Temporary Blockchain Storage**
- Blockchain stored in plain JSON for easy debugging
- Marked as temporary - can be cleared anytime
- Automatically loads on startup if available
- Provides transaction history persistence

## Storage Structure

```
data/
├── .key                    # Encryption key (auto-generated, hidden)
├── users.json.enc          # Encrypted user credentials
├── user_keys.json.enc      # Encrypted ElGamal keys
├── blockchain_temp.json    # Temporary blockchain (unencrypted)
└── backups/               # Optional backups
```

## Security Features

### Encryption
- **Algorithm**: Fernet (AES-128 in CBC mode with HMAC authentication)
- **Key Storage**: Stored in `.key` file (marked hidden on Windows)
- **Data Integrity**: HMAC ensures data hasn't been tampered with

### What's Encrypted
✅ User passwords (hashed then encrypted)  
✅ User email addresses  
✅ ElGamal private keys  
✅ User metadata  

### What's NOT Encrypted
❌ Blockchain data (temporary storage for debugging)  
❌ Active session data (in-memory only)  

## Usage

### Automatic Storage
The system automatically:
- Saves user data when registering/updating
- Loads user data on startup
- Saves blockchain blocks when added
- Loads blockchain on startup if available

### Manual Operations

```python
from src.core.storage import SecureStorage

storage = SecureStorage()

# Get storage information
info = storage.get_storage_info()

# Backup data
storage.backup_data()

# Clear temporary blockchain
storage.clear_blockchain_temp()
```

## Data Persistence

| Data Type | Persistence | Encryption | Auto-Save |
|-----------|-------------|------------|-----------|
| User Credentials | Permanent | ✅ Yes | ✅ Yes |
| ElGamal Keys | Permanent | ✅ Yes | ✅ Yes |
| Blockchain | Temporary | ❌ No | ✅ Yes |
| Active Sessions | Memory Only | N/A | ❌ No |

## Important Notes

### ⚠️ Encryption Key
- The `.key` file is **critical** - losing it means losing access to all encrypted data
- **DO NOT** commit `.key` file to version control
- **DO NOT** share the `.key` file
- Consider backing up the key securely

### 🗑️ Temporary Blockchain
- Blockchain storage is marked as "temporary"
- Clearing the blockchain doesn't affect user data
- In production, consider using a proper database

### 🔒 Security Best Practices
1. Keep the `data/` directory secure
2. Backup the `.key` file separately
3. Use strong passwords for user accounts
4. Consider encrypting the entire data directory

## Storage Information Menu

Access storage information from the application menu:
- **Not logged in**: Option 3
- **Logged in**: Option 5

Shows:
- Data directory location
- File existence and sizes
- Encryption status
- Number of users and blockchain blocks

## Backup and Recovery

### Creating Backups
The system can create backups of encrypted data:

```python
storage.backup_data()  # Creates timestamped backup
```

### Recovery
To restore from backup:
1. Copy backup files to the `data/` directory
2. Rename to original filenames
3. Restart the application

### Fresh Start
To start with clean data:
1. Delete the `data/` directory
2. Restart the application
3. New encryption key will be generated
4. Demo users will be created

## Development Notes

### Adding New Storage Fields

```python
# In storage.py
def save_custom_data(self, data):
    encrypted = self._encrypt_data(data)
    with open(self.custom_file, 'wb') as f:
        f.write(encrypted)
```

### Changing Encryption
To use different encryption:
1. Update `_load_or_generate_key()` method
2. Update `_encrypt_data()` and `_decrypt_data()` methods
3. Re-encrypt existing data

## Troubleshooting

### "Error loading users"
- Check if `.key` file exists
- Verify data files aren't corrupted
- Try deleting `data/` for fresh start

### "Encryption key not found"
- System will auto-generate a new key
- Previous encrypted data won't be accessible

### "Permission denied"
- Check file permissions on `data/` directory
- Ensure application has write access

## Dependencies

```bash
pip install cryptography>=41.0.0
```

## File Formats

### Encrypted User Data (users.json.enc)
```json
{
  "users": {
    "alice": {
      "password_hash": "...",
      "created_at": "2025-11-01 12:00:00",
      "email": "alice@example.com",
      "login_count": 5
    }
  },
  "last_updated": "2025-11-01 12:30:00",
  "version": "1.0"
}
```

### Temporary Blockchain (blockchain_temp.json)
```json
{
  "blockchain": [
    {
      "index": 0,
      "timestamp": "2025-11-01 12:00:00",
      "data": {...},
      "previous_hash": "0",
      "hash": "...",
      "nonce": 123
    }
  ],
  "saved_at": "2025-11-01 12:30:00",
  "note": "Temporary blockchain storage - cleared on restart"
}
```
