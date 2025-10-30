"""
Secure Messaging System - Server
Network-based server for multi-user messaging across terminals
"""

import socket
import threading
import json
import pickle
from datetime import datetime
from src.core.authentication import UserAuthentication
from src.core.classical_ciphers import CaesarCipher, VigenereCipher
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from src.core.hashing import MessageIntegrity
from src.core.blockchain import MessageBlockchain
from src.core.elgamal import ElGamal, KeyDistributionCenter


class MessageServer:
    """
    Multi-threaded server for handling multiple client connections
    """
    
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        
        # Initialize all components
        self.auth = UserAuthentication()
        self.kdc = KeyDistributionCenter()
        self.blockchain = MessageBlockchain(difficulty=2)
        self.user_keys = {}
        
        # Track connected clients
        self.clients = {}  # {username: client_socket}
        self.client_threads = []
        
        # Thread lock for synchronized access
        self.lock = threading.Lock()
        
        # Setup demo users
        self._setup_demo_users()
    
    def _setup_demo_users(self):
        """Setup demo users for testing"""
        demo_users = [
            ("alice", "alice123", "alice@example.com"),
            ("bob", "bob123", "bob@example.com"),
            ("charlie", "charlie123", "charlie@example.com"),
        ]
        
        for username, password, email in demo_users:
            success, _ = self.auth.register_user(username, password, email)
            if success:
                # Generate ElGamal keys
                key_pair = ElGamal.generate_keys(bits=16)
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)
                print(f"  ✓ Demo user '{username}' registered")
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print("\n" + "="*60)
            print(" "*15 + "SECURE MESSAGING SERVER")
            print("="*60)
            print(f"\n✓ Server started on {self.host}:{self.port}")
            print(f"✓ Waiting for connections...")
            print(f"✓ Press Ctrl+C to stop the server\n")
            
            # Accept connections
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] New connection from {address}")
                    
                    # Handle client in new thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.client_threads.append(client_thread)
                    
                except KeyboardInterrupt:
                    print("\n\n✓ Server shutting down...")
                    break
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
        
        except Exception as e:
            print(f"Error starting server: {e}")
        
        finally:
            self.stop()
    
    def _handle_client(self, client_socket, address):
        """Handle individual client connection"""
        username = None
        
        try:
            while self.running:
                # Receive request from client
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Parse request
                try:
                    request = json.loads(data.decode('utf-8'))
                    command = request.get('command')
                    
                    # Handle different commands
                    if command == 'LOGIN':
                        response = self._handle_login(request, client_socket)
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
                    
                    # Send response
                    self._send_response(client_socket, response)
                
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    self._send_response(client_socket, error_response)
        
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        
        finally:
            # Cleanup
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} disconnected")
            
            client_socket.close()
    
    def _send_response(self, client_socket, response):
        """Send JSON response to client"""
        try:
            response_json = json.dumps(response)
            client_socket.send(response_json.encode('utf-8'))
        except Exception as e:
            print(f"Error sending response: {e}")
    
    def _handle_login(self, request, client_socket):
        """Handle login request"""
        username = request.get('username')
        password = request.get('password')
        
        success, message = self.auth.login(username, password)
        
        if success:
            with self.lock:
                self.clients[username] = client_socket
            
            session_id = message.split(": ")[1]
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} logged in")
            
            return {
                'status': 'success',
                'message': 'Login successful',
                'session_id': session_id,
                'username': username
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
            # Generate ElGamal keys
            key_pair = ElGamal.generate_keys(bits=16)
            with self.lock:
                self.user_keys[username] = key_pair
                self.kdc.register_user(username, key_pair)
            
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
        
        # Verify receiver exists
        if not self.kdc.is_user_registered(receiver):
            return {'status': 'error', 'message': f"User '{receiver}' not found"}
        
        # Compute hash
        message_hash = MessageIntegrity.compute_hash(plaintext)
        
        # Encrypt message based on method
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
                # Store key for receiver
                encryption_params['key_hex'] = cipher.get_key_hex()
            
            elif encryption_method == 'Block':
                key = encryption_params.get('key')
                cipher = MiniBlockCipher(key=key if key else None)
                ciphertext = cipher.encrypt(plaintext)
                # Store key for receiver
                encryption_params['key_hex'] = cipher.get_key_hex()
            
            else:
                return {'status': 'error', 'message': 'Invalid encryption method'}
            
            # Add to blockchain
            with self.lock:
                block = self.blockchain.add_message_block(
                    sender=sender,
                    receiver=receiver,
                    ciphertext=str(ciphertext),
                    message_hash=message_hash,
                    encryption_method=encryption_method
                )
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Message: {sender} -> {receiver} (Block #{block.index})")
            
            # Notify receiver if online
            if receiver in self.clients:
                notification = {
                    'type': 'NEW_MESSAGE',
                    'from': sender,
                    'timestamp': block.timestamp
                }
                try:
                    self._send_response(self.clients[receiver], notification)
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
        
        # Filter out current user
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
        
        # Close all client connections
        with self.lock:
            for username, client_socket in self.clients.items():
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("\n✓ Server stopped")


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
