"""
Secure Communication Protocol
Integrates key exchange, AEAD encryption, key management, and forward secrecy into a complete secure messaging protocol.
"""

import json
import secrets
import time
from typing import Dict, Optional, Tuple
from datetime import datetime

from .key_exchange import (
    generate_private_key,
    generate_public_key,
    compute_shared_secret,
    derive_session_key,
    DEMO_P,
    DEMO_G
)
from .aead import encrypt as aead_encrypt, decrypt as aead_decrypt
from .km import KeyManager
from .postquantum import EphemeralDH


class SecureSession:
    """
    Represents a secure communication session between client and server.
    Combines all security concepts:
    - Ephemeral DH keys (forward secrecy)
    - Session key derived from key exchange
    - AEAD encryption for all messages
    - Key rotation support
    """
    
    def __init__(self, session_id: str, is_server: bool = False):
        self.session_id = session_id
        self.is_server = is_server
        self.created_at = time.time()
        
        # Ephemeral keys for forward secrecy
        self.ephemeral_dh = EphemeralDH()
        
        # Session key from key exchange
        self.session_key: Optional[bytes] = None
        
        # Message counter for nonce generation (prevents replay)
        self.message_counter = 0
        
        # Track key rotation
        self.key_rotated_at: Optional[float] = None
        self.messages_encrypted = 0
        
        # Security parameters
        self.max_messages_before_rotation = 1000
        self.max_session_age_seconds = 3600  # 1 hour
        
    def get_public_key(self) -> int:
        """Get ephemeral public key for key exchange."""
        return self.ephemeral_dh.public_key
    
    def complete_key_exchange(self, their_public_key: int) -> bytes:
        """
        Complete Diffie-Hellman key exchange and derive session key.
        """
        self.session_key = self.ephemeral_dh.compute_session_key(their_public_key)
        return self.session_key
    
    def needs_rotation(self) -> bool:
        """
        Determine if key rotation is needed.
        Rotate keys based on:
        - Number of messages encrypted
        - Session age
        """
        if self.messages_encrypted >= self.max_messages_before_rotation:
            return True
        
        age = time.time() - self.created_at
        if age >= self.max_session_age_seconds:
            return True
        
        return False
    
    def rotate_key(self) -> Tuple[int, int]:
        """
        Perform key rotation.
        Generate new ephemeral keys and return them for re-exchange.
        """
        # Destroy old ephemeral keys (forward secrecy)
        self.ephemeral_dh.destroy_keys()
        
        # Generate new ephemeral keys
        self.ephemeral_dh = EphemeralDH()
        self.key_rotated_at = time.time()
        self.messages_encrypted = 0
        
        return self.ephemeral_dh.public_key, self.ephemeral_dh.private_key
    
    def encrypt_message(self, plaintext: str, metadata: Optional[Dict] = None) -> Dict:
        """
        Encrypt message using AEAD.
        
        Returns:
            Dictionary with ciphertext, tag, nonce, and metadata
        """
        if not self.session_key:
            raise RuntimeError("Session key not established. Complete key exchange first.")
        
        # Generate unique nonce (NEVER reuse with same key!)
        self.message_counter += 1
        nonce = self.message_counter.to_bytes(16, 'big')
        
        # Prepare AAD (Additional Authenticated Data)
        aad_dict = {
            'session_id': self.session_id,
            'timestamp': time.time(),
            'counter': self.message_counter
        }
        if metadata:
            aad_dict.update(metadata)
        
        aad = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
        
        # AEAD encrypt
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext, tag = aead_encrypt(self.session_key, nonce, aad, plaintext_bytes)
        
        self.messages_encrypted += 1
        
        return {
            'ciphertext': ciphertext.hex(),
            'tag': tag.hex(),
            'nonce': nonce.hex(),
            'aad': aad_dict,
            'counter': self.message_counter
        }
    
    def decrypt_message(self, encrypted_data: Dict) -> str:
        """
        Decrypt and verify message using AEAD.
        
        Args:
            encrypted_data: Dictionary with ciphertext, tag, nonce, aad
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            ValueError: If authentication fails (tampering detected)
        """
        if not self.session_key:
            raise RuntimeError("Session key not established. Complete key exchange first.")
        
        # Extract components
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        tag = bytes.fromhex(encrypted_data['tag'])
        nonce = bytes.fromhex(encrypted_data['nonce'])
        
        # Reconstruct AAD
        aad = json.dumps(encrypted_data['aad'], sort_keys=True).encode('utf-8')
        
        # AEAD decrypt and verify
        plaintext_bytes = aead_decrypt(self.session_key, nonce, aad, ciphertext, tag)
        
        return plaintext_bytes.decode('utf-8')
    
    def destroy(self):
        """
        Destroy session and keys (forward secrecy).
        After this, past messages cannot be decrypted.
        """
        self.ephemeral_dh.destroy_keys()
        if self.session_key:
            # Overwrite key material
            self.session_key = b'\x00' * len(self.session_key)
        print(f"[Security] Session {self.session_id} destroyed - forward secrecy achieved")


class SecureProtocol:
    """
    Complete secure communication protocol manager.
    Integrates:
    - Session establishment with DH key exchange
    - AEAD encrypted messages
    - Key lifecycle management
    - Forward secrecy with ephemeral keys
    """
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        
        # Key manager for session keys
        self.key_manager = KeyManager()
        
        # Active sessions
        self.sessions: Dict[str, SecureSession] = {}
        
    def create_session(self, session_id: Optional[str] = None) -> SecureSession:
        """
        Create a new secure session with ephemeral keys.
        Each session gets fresh ephemeral keys (forward secrecy).
        """
        if session_id is None:
            session_id = f"session-{secrets.token_hex(8)}"
        
        session = SecureSession(session_id, is_server=self.is_server)
        self.sessions[session_id] = session
        
        print(f"[Security] Created session {session_id} with ephemeral DH keys")
        print(f"  - Public key: {hex(session.get_public_key())[:32]}...")
        
        return session
    
    def initiate_handshake(self, session_id: str) -> Dict:
        """
        Initiate secure handshake (client side).
        Send public key for DH exchange.
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        handshake_data = {
            'type': 'HANDSHAKE_INIT',
            'session_id': session_id,
            'public_key': session.get_public_key(),
            'p': DEMO_P,
            'g': DEMO_G,
            'timestamp': time.time()
        }
        
        print(f"[Security] Initiating handshake for session {session_id}")
        return handshake_data
    
    def respond_to_handshake(self, handshake_init: Dict) -> Tuple[Dict, SecureSession]:
        """
        Respond to handshake (server side).
        Complete DH key exchange.
        """
        session_id = handshake_init['session_id']
        their_public_key = handshake_init['public_key']
        
        # Create session for this connection
        session = self.create_session(session_id)
        
        # Complete key exchange
        session.complete_key_exchange(their_public_key)
        
        handshake_response = {
            'type': 'HANDSHAKE_RESPONSE',
            'session_id': session_id,
            'public_key': session.get_public_key(),
            'timestamp': time.time()
        }
        
        print(f"[Security] Handshake complete for session {session_id}")
        print(f"  - Session key established: {session.session_key.hex()[:32]}...")
        
        return handshake_response, session
    
    def complete_handshake(self, session_id: str, handshake_response: Dict):
        """
        Complete handshake (client side).
        Derive shared session key.
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        their_public_key = handshake_response['public_key']
        
        # Complete key exchange
        session.complete_key_exchange(their_public_key)
        
        print(f"[Security] Handshake complete for session {session_id}")
        print(f"  - Session key established: {session.session_key.hex()[:32]}...")
    
    def send_secure_message(self, session_id: str, message: str, metadata: Optional[Dict] = None) -> Dict:
        """
        Encrypt and send message securely.
        AEAD encryption with authentication and rotation checks.
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        # Check if rotation needed
        if session.needs_rotation():
            print(f"[Security] Key rotation needed for session {session_id}")
            return {
                'type': 'KEY_ROTATION_REQUIRED',
                'session_id': session_id,
                'reason': 'Message limit or session age exceeded'
            }
        
        # AEAD encryption
        encrypted = session.encrypt_message(message, metadata)
        encrypted['type'] = 'SECURE_MESSAGE'
        encrypted['session_id'] = session_id
        
        return encrypted
    
    def receive_secure_message(self, session_id: str, encrypted_data: Dict) -> str:
        """
        Receive and decrypt secure message.
        AEAD decryption with authentication verification.
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        # AEAD decrypt
        plaintext = session.decrypt_message(encrypted_data)
        
        return plaintext
    
    def rotate_session_key(self, session_id: str) -> Dict:
        """
        Perform key rotation for a session.
        Key rotation with new ephemeral keys.
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        
        print(f"[Security] Rotating keys for session {session_id}")
        
        # Generate new ephemeral keys
        new_public_key, _ = session.rotate_key()
        
        return {
            'type': 'KEY_ROTATION',
            'session_id': session_id,
            'new_public_key': new_public_key,
            'timestamp': time.time()
        }
    
    def complete_key_rotation(self, session_id: str, rotation_data: Dict):
        """
        Complete key rotation (other party's response).
        Re-establish session key with new ephemeral keys.
        """
        if session_id not in self.sessions:
            raise ValueError(f"Session {session_id} not found")
        
        session = self.sessions[session_id]
        their_new_public_key = rotation_data['new_public_key']
        
        # Re-compute session key with new ephemeral keys
        session.complete_key_exchange(their_new_public_key)
        
        print(f"[Security] Key rotation complete for session {session_id}")
        print(f"  - New session key: {session.session_key.hex()[:32]}...")
    
    def destroy_session(self, session_id: str):
        """
        Destroy session and all keys.
        Ensure forward secrecy.
        """
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.destroy()
            del self.sessions[session_id]
    
    def get_session_info(self, session_id: str) -> Dict:
        """Get detailed information about a session (for demonstration)."""
        if session_id not in self.sessions:
            return {'error': 'Session not found'}
        
        session = self.sessions[session_id]
        
        return {
            'session_id': session_id,
            'created_at': datetime.fromtimestamp(session.created_at).strftime('%Y-%m-%d %H:%M:%S'),
            'age_seconds': time.time() - session.created_at,
            'messages_encrypted': session.messages_encrypted,
            'needs_rotation': session.needs_rotation(),
            'has_session_key': session.session_key is not None,
            'key_rotated_at': datetime.fromtimestamp(session.key_rotated_at).strftime('%Y-%m-%d %H:%M:%S') if session.key_rotated_at else 'Never'
        }
