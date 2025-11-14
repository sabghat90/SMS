"""
Secure Messaging System - Server
Network-based server for multi-user messaging across terminals
Now with Labs 12-15 security: DH key exchange, AEAD, key rotation, forward secrecy
"""

import socket
import threading
import json
from datetime import datetime
from src.core.authentication import UserAuthentication
from src.core.classical_ciphers import CaesarCipher, VigenereCipher
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from src.core.hashing import MessageIntegrity
from src.core.blockchain import MessageBlockchain
from src.core.elgamal import ElGamal, KeyDistributionCenter, ElGamalKeyPair
from src.core.storage import SecureStorage
from src.core.secure_protocol import SecureProtocol


class MessageServer:
    """
    Multi-threaded server for handling multiple client connections
    """
    
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        self.storage = SecureStorage(data_dir="data")
        
        self.auth = UserAuthentication(storage=self.storage)
        self.kdc = KeyDistributionCenter()
        self.blockchain = MessageBlockchain(difficulty=2, storage=self.storage)
        
        self.user_keys = {}
        stored_keys = self.storage.load_user_keys()
        
        for username, key_data in stored_keys.items():
            if isinstance(key_data, dict):
                key_obj = ElGamalKeyPair(
                    p=key_data['p'],
                    g=key_data['g'],
                    private_key=key_data['private_key'],
                    public_key=key_data['public_key']
                )
                self.user_keys[username] = key_obj
                self.kdc.register_user(username, key_obj)
        
        # Labs 12-15: Secure protocol for DH handshake, AEAD, key rotation, forward secrecy
        self.protocol = SecureProtocol(is_server=True)
        
        self.clients = {}  # {username: (client_socket, session_id)}
        self.sessions = {}  # {session_id: username}
        self.client_threads = []
        
        self.lock = threading.Lock()
        
        self._setup_demo_users()
    
    def _setup_demo_users(self):
        """Setup demo users for testing"""
        if len(self.auth.users) > 0:
            print(f"Found {len(self.auth.users)} existing users in storage.")
            return
        
        demo_users = [
            ("alice", "alice123", "alice@example.com"),
            ("bob", "bob123", "bob@example.com"),
            ("charlie", "charlie123", "charlie@example.com"),
        ]
        
        print("Setting up demo users...")
        for username, password, email in demo_users:
            success, _ = self.auth.register_user(username, password, email)
            if success:
                key_pair = ElGamal.generate_keys(bits=16)
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)
                print(f"Demo user '{username}' registered")
        
        if self.user_keys:
            self.storage.save_user_keys(self.user_keys)
            print("User keys saved to storage")
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print("\n" + "="*60)
            print(" "*15 + " SECURE MESSAGING SERVER ")
            print("="*60)
            print(f"\nServer started on {self.host}:{self.port}")
            print(f"\n Security Features Enabled:")
            print(f"  • Lab 12: Diffie-Hellman Key Exchange")
            print(f"  • Lab 13: AEAD Encryption")
            print(f"  • Lab 14: Automatic Key Rotation")
            print(f"  • Lab 15: Forward Secrecy")
            print(f"\nWaiting for connections...")
            print(f"Press Ctrl+C to stop the server\n")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] New connection from {address}")
                    
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.client_threads.append(client_thread)
                    
                except KeyboardInterrupt:
                    print("\n\nServer shutting down...")
                    break
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
        
        except Exception as e:
            print(f"Error starting server: {e}")
        
        finally:
            self.stop()
    
    def _handle_client(self, client_socket, address):
        """Handle individual client connection with Labs 12-15 security"""
        username = None
        session_id = None
        secure_mode = False
        
        try:
            # Set socket timeout to prevent hanging
            client_socket.settimeout(30.0)
            
            while self.running:
                try:
                    data = client_socket.recv(16384)  # Increased buffer for encrypted data
                    if not data:
                        break
                    
                    request = json.loads(data.decode('utf-8'))
                    msg_type = request.get('type')
                    command = request.get('command')
                    
                    # Lab 12: Handle DH handshake
                    if msg_type == 'HANDSHAKE_INIT':
                        print(f"[Security] DH handshake initiated from {address}")
                        response = self._handle_handshake(request)
                        session_id = request['session_id']
                        secure_mode = True
                        self._send_response(client_socket, response)
                        continue
                    
                    # Lab 13: Handle AEAD encrypted messages
                    elif msg_type == 'SECURE_MESSAGE' and secure_mode:
                        response = self._handle_secure_message(request, session_id)
                        self._send_response(client_socket, response)
                        continue
                    
                    # Lab 14: Handle key rotation
                    elif msg_type == 'KEY_ROTATION' and secure_mode:
                        print(f"[Security] Key rotation requested for session {session_id}")
                        response = self._handle_key_rotation(request)
                        self._send_response(client_socket, response)
                        continue
                    
                    # Regular commands (backward compatibility)
                    if command == 'LOGIN':
                        response = self._handle_login(request, client_socket, session_id)
                        if response['status'] == 'success':
                            username = request['username']
                    
                    elif command == 'REGISTER':
                        response = self._handle_register(request)
                    
                    elif command == 'SEND_MESSAGE':
                        response = self._handle_send_message(request)
                    
                    elif command == 'GET_MESSAGES':
                        response = self._handle_get_messages(request)
                    
                    elif command == 'GET_USERS':
                        response = self._handle_get_users(request)
                    
                    elif command == 'VERIFY_BLOCKCHAIN':
                        response = self._handle_verify_blockchain()
                    
                    elif command == 'GET_BLOCKCHAIN':
                        response = self._handle_get_blockchain()
                    
                    elif command == 'LOGOUT':
                        response = {'status': 'success', 'message': 'Logged out'}
                        self._send_response(client_socket, response)
                        break
                    
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}
                    
                    self._send_response(client_socket, response)
                
                except socket.timeout:
                    continue  # Continue waiting for data
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    self._send_response(client_socket, error_response)
        
        except socket.timeout:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Client {address} timed out")
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        
        finally:
            # Lab 15: Clean up session (forward secrecy)
            if session_id and session_id in self.protocol.sessions:
                self.protocol.destroy_session(session_id)
                print(f"[Security] Session {session_id} destroyed (forward secrecy)")
            
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                    if session_id and session_id in self.sessions:
                        del self.sessions[session_id]
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} disconnected")
            
            client_socket.close()
    
    def _send_response(self, client_socket, response):
        """Send JSON response to client"""
        try:
            response_json = json.dumps(response)
            client_socket.send(response_json.encode('utf-8'))
        except Exception as e:
            print(f"Error sending response: {e}")
    
    def _handle_handshake(self, request):
        """Handle secure handshake (Lab 12: DH Key Exchange)"""
        try:
            handshake_response, session = self.protocol.respond_to_handshake(request)
            session_id = request['session_id']
            self.sessions[session_id] = None  # Username set on login
            return handshake_response
        except Exception as e:
            return {'status': 'error', 'message': f'Handshake failed: {str(e)}'}
    
    def _handle_secure_message(self, request, session_id):
        """Handle secure encrypted message (Lab 13: AEAD)"""
        try:
            if session_id not in self.protocol.sessions:
                return {'status': 'error', 'message': 'Invalid session'}
            
            # Decrypt the message
            decrypted = self.protocol.receive_secure_message(session_id, request)
            command_data = json.loads(decrypted)
            
            # Process the command
            response = self._process_command(command_data, session_id)
            
            # Encrypt the response
            response_json = json.dumps(response)
            encrypted_response = self.protocol.send_secure_message(
                session_id, response_json, {'response_to': command_data.get('command')}
            )
            return encrypted_response
        except Exception as e:
            return {'status': 'error', 'message': f'Secure message failed: {str(e)}'}
    
    def _handle_key_rotation(self, request):
        """Handle key rotation request (Lab 14)"""
        try:
            session_id = request['session_id']
            rotation_response = self.protocol.rotate_session_key(session_id)
            self.protocol.complete_key_rotation(session_id, request)
            return rotation_response
        except Exception as e:
            return {'status': 'error', 'message': f'Key rotation failed: {str(e)}'}
    
    def _process_command(self, request, session_id):
        """Process command (for both secure and regular modes)"""
        command = request.get('command')
        
        if command == 'LOGIN':
            return self._handle_login(request, None, session_id)
        elif command == 'SEND_MESSAGE':
            return self._handle_send_message(request)
        elif command == 'GET_MESSAGES':
            return self._handle_get_messages(request)
        elif command == 'GET_USERS':
            return self._handle_get_users(request)
        elif command == 'VERIFY_BLOCKCHAIN':
            return self._handle_verify_blockchain()
        elif command == 'GET_BLOCKCHAIN':
            return self._handle_get_blockchain()
        else:
            return {'status': 'error', 'message': 'Unknown command'}
    
    def _handle_login(self, request, client_socket, session_id=None):
        """Handle login request"""
        username = request.get('username')
        password = request.get('password')
        
        success, message = self.auth.login(username, password)
        
        if success:
            with self.lock:
                if client_socket:
                    self.clients[username] = (client_socket, session_id)
                if session_id:
                    self.sessions[session_id] = username
            
            auth_session_id = message.split(": ")[1] if ": " in message else None
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} logged in" + 
                  (f" (secure session: {session_id})" if session_id else ""))
            
            return {
                'status': 'success',
                'message': 'Login successful',
                'session_id': auth_session_id or session_id,
                'username': username,
                'secure_session': session_id is not None
            }
        else:
            return {'status': 'error', 'message': message}
    
    def _handle_register(self, request):
        """Handle registration request"""
        username = request.get('username')
        password = request.get('password')
        email = request.get('email', '')
        
        success, message = self.auth.register_user(username, password, email)
        
        if success:
            key_pair = ElGamal.generate_keys(bits=16)
            with self.lock:
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)
                self.storage.save_user_keys(self.user_keys)
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] New user registered: {username}")
            
            return {
                'status': 'success',
                'message': message,
                'key_info': {
                    'p': key_pair.p,
                    'g': key_pair.g,
                    'public_key': key_pair.public_key
                }
            }
        else:
            return {'status': 'error', 'message': message}
    
    def _handle_send_message(self, request):
        """Handle send message request"""
        sender = request.get('sender')
        receiver = request.get('receiver')
        plaintext = request.get('plaintext')
        encryption_method = request.get('encryption_method')
        encryption_params = request.get('encryption_params', {})
        
        # Check receiver exists (no lock needed)
        if not self.kdc.is_user_registered(receiver):
            return {'status': 'error', 'message': f"User '{receiver}' not found"}
        
        message_hash = MessageIntegrity.compute_hash(plaintext)
        
        try:
            if encryption_method == 'Caesar':
                shift = encryption_params.get('shift', 3)
                cipher = CaesarCipher(shift=shift)
                ciphertext = cipher.encrypt(plaintext)
            
            elif encryption_method == 'Vigenere':
                key = encryption_params.get('key', 'KEY')
                cipher = VigenereCipher(key=key)
                ciphertext = cipher.encrypt(plaintext)
            
            elif encryption_method == 'XOR':
                key = encryption_params.get('key')
                cipher = XORStreamCipher(key=key if key else None)
                ciphertext = cipher.encrypt(plaintext)
                encryption_params['key_hex'] = cipher.get_key_hex()
            
            elif encryption_method == 'Block':
                key = encryption_params.get('key')
                cipher = MiniBlockCipher(key=key if key else None)
                ciphertext = cipher.encrypt(plaintext)
                encryption_params['key_hex'] = cipher.get_key_hex()
            
            else:
                return {'status': 'error', 'message': 'Invalid encryption method'}
            
            # Only lock for blockchain operations (minimized lock time)
            with self.lock:
                block = self.blockchain.add_message_block(
                    sender=sender,
                    receiver=receiver,
                    ciphertext=str(ciphertext),
                    message_hash=message_hash,
                    encryption_method=encryption_method
                )
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Message: {sender} -> {receiver} (Block #{block.index})")
            
            # Notify receiver (outside lock to avoid blocking)
            if receiver in self.clients:
                notification = {
                    'type': 'NEW_MESSAGE',
                    'from': sender,
                    'timestamp': block.timestamp
                }
                try:
                    receiver_socket = self.clients[receiver][0]  # Get socket from tuple
                    self._send_response(receiver_socket, notification)
                except:
                    pass
            
            return {
                'status': 'success',
                'message': 'Message sent successfully',
                'block_index': block.index,
                'block_hash': block.hash,
                'message_hash': message_hash,
                'encryption_params': encryption_params
            }
        
        except Exception as e:
            return {'status': 'error', 'message': f'Encryption failed: {str(e)}'}
    
    def _handle_get_messages(self, request):
        """Handle get messages request"""
        username = request.get('username')
        
        with self.lock:
            messages = self.blockchain.get_messages_for_user(username)
        
        message_list = []
        for block in messages:
            data = block.data
            message_list.append({
                'block_index': block.index,
                'timestamp': block.timestamp,
                'sender': data['sender'],
                'receiver': data['receiver'],
                'ciphertext': data['ciphertext'],
                'message_hash': data['message_hash'],
                'encryption_method': data['encryption_method'],
                'block_hash': block.hash
            })
        
        return {
            'status': 'success',
            'messages': message_list,
            'count': len(message_list)
        }
    
    def _handle_get_users(self, request):
        """Handle get users list request"""
        current_user = request.get('username')
        
        with self.lock:
            all_users = self.kdc.list_registered_users()
            online_users = list(self.clients.keys())
        
        available_users = [u for u in all_users if u != current_user]
        
        return {
            'status': 'success',
            'users': available_users,
            'online_users': online_users
        }
    
    def _handle_verify_blockchain(self):
        """Handle blockchain verification request"""
        with self.lock:
            is_valid, message = self.blockchain.is_chain_valid()
        
        return {
            'status': 'success',
            'is_valid': is_valid,
            'message': message,
            'chain_length': self.blockchain.get_chain_length()
        }
    
    def _handle_get_blockchain(self):
        """Handle get blockchain request"""
        with self.lock:
            blocks = []
            for block in self.blockchain.chain:
                blocks.append({
                    'index': block.index,
                    'timestamp': block.timestamp,
                    'data': block.data,
                    'previous_hash': block.previous_hash,
                    'hash': block.hash,
                    'nonce': block.nonce
                })
        
        return {
            'status': 'success',
            'blocks': blocks,
            'chain_length': len(blocks)
        }
    
    def stop(self):
        """Stop the server"""
        self.running = False
        
        with self.lock:
            for username, client_socket in self.clients.items():
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("\nServer stopped")


def main():
    """Entry point"""
    server = MessageServer(host='127.0.0.1', port=5555)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    except Exception as e:
        print(f"\nServer error: {e}")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
