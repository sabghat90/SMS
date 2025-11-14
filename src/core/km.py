"""Lab 14 - Key Management

Demonstrates secure key lifecycle management including:
- Key generation and storage
- Key rotation (graceful key replacement)
- Key revocation (emergency key invalidation)
- Key metadata tracking

Real-world applications: KMS (Key Management Service), HSM integration,
credential rotation in cloud services.

Educational implementation suitable for classroom demonstrations.
"""
import time
import secrets
import json
from typing import Dict, Optional, List
from datetime import datetime


class KeyEntry:
    """Represents a cryptographic key with metadata."""
    
    def __init__(self, key: bytes, key_type: str = "symmetric"):
        self.key = key
        self.key_type = key_type
        self.created = time.time()
        self.revoked = False
        self.revoked_at: Optional[float] = None
        self.rotated_to: Optional[str] = None  # ID of replacement key
        self.usage_count = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "key": self.key.hex(),
            "key_type": self.key_type,
            "created": self.created,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "rotated_to": self.rotated_to,
            "usage_count": self.usage_count
        }


class KeyManager:
    """
    Educational Key Management System for demonstrating key lifecycle.
    
    Features:
    - Create keys with unique IDs
    - Retrieve active keys
    - Rotate keys (create new, mark old as rotated)
    - Revoke keys (emergency invalidation)
    - Track key usage and metadata
    """
    
    def __init__(self):
        self._store: Dict[str, KeyEntry] = {}
        self._rotation_history: List[tuple] = []
    
    def create_key(self, key_id: Optional[str] = None, length: int = 32, 
                   key_type: str = "symmetric") -> str:
        """
        Create a new cryptographic key.
        
        Args:
            key_id: Optional custom key ID (auto-generated if None)
            length: Key length in bytes
            key_type: Type of key (symmetric, session, etc.)
            
        Returns:
            The key ID
        """
        if key_id is None:
            key_id = f"key-{secrets.token_hex(8)}"
        
        if key_id in self._store:
            raise ValueError(f"Key ID '{key_id}' already exists")
        
        key_material = secrets.token_bytes(length)
        self._store[key_id] = KeyEntry(key_material, key_type)
        
        print(f"Created key '{key_id}' ({length} bytes, type={key_type})")
        return key_id
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve an active key.
        
        Args:
            key_id: The key identifier
            
        Returns:
            Key material if active, None if revoked/missing
        """
        entry = self._store.get(key_id)
        if not entry or entry.revoked:
            return None
        
        entry.usage_count += 1
        return entry.key
    
    def rotate_key(self, old_key_id: str, new_key_id: Optional[str] = None) -> Optional[str]:
        """
        Rotate a key (create new key, mark old as rotated).
        
        Key rotation is critical for:
        - Limiting damage from key compromise
        - Meeting compliance requirements
        - Graceful key replacement without service interruption
        
        Args:
            old_key_id: Key to rotate
            new_key_id: Optional ID for new key
            
        Returns:
            New key ID, or None if old key doesn't exist
        """
        if old_key_id not in self._store:
            print(f"Key '{old_key_id}' not found")
            return None
        
        old_entry = self._store[old_key_id]
        
        # Create new key with same properties
        if new_key_id is None:
            new_key_id = f"key-{secrets.token_hex(8)}"
        
        new_key_material = secrets.token_bytes(len(old_entry.key))
        self._store[new_key_id] = KeyEntry(new_key_material, old_entry.key_type)
        
        # Mark old key as rotated (not revoked - may still be used temporarily)
        old_entry.rotated_to = new_key_id
        
        # Record rotation history
        self._rotation_history.append((old_key_id, new_key_id, time.time()))
        
        print(f"Rotated key '{old_key_id}' -> '{new_key_id}'")
        return new_key_id
    
    def revoke_key(self, key_id: str, reason: str = "unspecified") -> bool:
        """
        Revoke a key (emergency invalidation).
        
        Revocation is used when:
        - Key compromise is suspected
        - Service is decommissioned
        - Security policy requires immediate invalidation
        
        Args:
            key_id: Key to revoke
            reason: Reason for revocation (for audit)
            
        Returns:
            True if revoked, False if key doesn't exist
        """
        if key_id not in self._store:
            print(f"Key '{key_id}' not found")
            return False
        
        entry = self._store[key_id]
        if entry.revoked:
            print(f"Key '{key_id}' already revoked")
            return True
        
        entry.revoked = True
        entry.revoked_at = time.time()
        
        print(f"Revoked key '{key_id}' (reason: {reason})")
        return True
    
    def list_keys(self, include_revoked: bool = False) -> List[str]:
        """
        List all key IDs.
        
        Args:
            include_revoked: Whether to include revoked keys
            
        Returns:
            List of key IDs
        """
        if include_revoked:
            return list(self._store.keys())
        return [kid for kid, entry in self._store.items() if not entry.revoked]
    
    def get_key_info(self, key_id: str) -> Optional[dict]:
        """Get metadata about a key."""
        entry = self._store.get(key_id)
        if not entry:
            return None
        
        return {
            "key_id": key_id,
            "type": entry.key_type,
            "created": datetime.fromtimestamp(entry.created).isoformat(),
            "revoked": entry.revoked,
            "revoked_at": datetime.fromtimestamp(entry.revoked_at).isoformat() if entry.revoked_at else None,
            "rotated_to": entry.rotated_to,
            "usage_count": entry.usage_count,
            "age_seconds": time.time() - entry.created
        }
    
    def get_rotation_history(self) -> List[dict]:
        """Get key rotation history."""
        return [
            {
                "old_key": old,
                "new_key": new,
                "rotated_at": datetime.fromtimestamp(ts).isoformat()
            }
            for old, new, ts in self._rotation_history
        ]


def demo() -> bool:
    """
    Demonstrate key lifecycle management operations.
    
    Returns:
        True if all operations succeed
    """
    print("Lab 14: Key Management Demo")
    print("=" * 50)
    
    km = KeyManager()
    
    # Create keys
    print("\n1. Creating keys...")
    key1 = km.create_key(key_type="session")
    key2 = km.create_key(key_type="storage")
    key3 = km.create_key("custom-key-id", key_type="symmetric")
    
    # Retrieve keys
    print("\n2. Retrieving keys...")
    k1 = km.get_key(key1)
    print(f"Retrieved key '{key1}': {k1.hex()[:32]}... ({len(k1)} bytes)")
    
    # Key info
    print("\n3. Key metadata...")
    info = km.get_key_info(key1)
    print(f"Key info: {json.dumps(info, indent=2)}")
    
    # Rotate key
    print("\n4. Rotating key...")
    new_key = km.rotate_key(key1)
    print(f"Old key '{key1}' rotated to '{new_key}'")
    
    # Verify old key still works temporarily (grace period)
    old_still_works = km.get_key(key1) is not None
    print(f"Old key still accessible: {old_still_works}")
    
    # Revoke old key
    print("\n5. Revoking old key...")
    km.revoke_key(key1, reason="rotation complete")
    
    # Verify old key no longer works
    old_revoked = km.get_key(key1) is None
    print(f"Old key now inaccessible: {old_revoked}")
    
    # New key still works
    new_works = km.get_key(new_key) is not None
    print(f"New key works: {new_works}")
    
    # List keys
    print("\n6. Active keys:")
    for kid in km.list_keys():
        print(f"  - {kid}")
    
    # Rotation history
    print("\n7. Rotation history:")
    for event in km.get_rotation_history():
        print(f"  {event['old_key']} -> {event['new_key']} at {event['rotated_at']}")
    
    print("\nKey management operations complete!")
    return old_revoked and new_works


if __name__ == "__main__":
    demo()
