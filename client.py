"""
Secure Messaging System - Client
Network client for connecting to the messaging server
Run this in separate terminals for different users
"""

import socket
import json
import secrets
import threading
from src.core.classical_ciphers import CaesarCipher, VigenereCipher
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from src.core.hashing import MessageIntegrity
from src.core.secure_protocol import SecureProtocol


class MessageClient:
    """
    Client application for secure messaging
    """
    
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None
        self.session_id = None
        self.running = False
        
        # Secure protocol for DH handshake, AEAD, key rotation, forward secrecy
        self.protocol = SecureProtocol(is_server=False)
        self.secure_session_id = None
        self.secure_mode = False
        
        self.notification_thread = None
    
    def connect(self):
        """Connect to server and establish secure session"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.running = True
            print(f"\nConnected to server at {self.host}:{self.port}")
            
            # Always establish secure session for transport layer security
            print("\n[Security] Establishing secure transport layer...")
            return self._establish_secure_session()
            
        except Exception as e:
            print(f"\nCould not connect to server: {e}")
            print(f"Make sure the server is running!")
            return False
    
    def disconnect(self):
        """Disconnect from server and destroy session"""
        self.running = False
        
        if self.connected and self.username:
            if self.secure_mode:
                self._send_secure_command({'command': 'LOGOUT'})
            else:
                self._send_request({'command': 'LOGOUT'})
        
        # Destroy session for forward secrecy
        if self.secure_session_id and self.secure_session_id in self.protocol.sessions:
            self.protocol.destroy_session(self.secure_session_id)
            print("\n[Security] Session destroyed - forward secrecy achieved")
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.connected = False
        print("\nDisconnected from server")
    
    def _establish_secure_session(self):
        """Establish secure session using DH key exchange"""
        try:
            print("\n[Security] Establishing secure session...")
            
            # Create session and initiate handshake
            self.secure_session_id = f"client-{secrets.token_hex(8)}"
            session = self.protocol.create_session(self.secure_session_id)
            
            print(f"\n[Security] Generated ephemeral DH keys")
            print(f"  Public key: {hex(session.get_public_key())[:40]}...")
            
            # Send handshake
            handshake_init = self.protocol.initiate_handshake(self.secure_session_id)
            self._send_request(handshake_init)
            
            # Receive handshake response
            handshake_response = self._receive_response()
            
            if handshake_response and handshake_response.get('type') == 'HANDSHAKE_RESPONSE':
                # Complete handshake
                self.protocol.complete_handshake(self.secure_session_id, handshake_response)
                self.secure_mode = True
                
                session_key = self.protocol.sessions[self.secure_session_id].session_key
                print(f"\nSecure transport layer established!")
                print(f"  Session ID: {self.secure_session_id}")
                print(f"  Session key: {session_key.hex()[:40]}...")
                print(f"\n[Security] Transport Layer: AEAD encrypted")
                print(f"[Security] Message Layer: You can choose classical ciphers")
                print(f"\nCombined Mode: Secure transport + Educational ciphers")
                
                return True
            else:
                print(f"\nHandshake failed")
                self.secure_mode = False
                return True
                
        except Exception as e:
            print(f"\nSecure session establishment failed: {e}")
            print("Falling back to basic mode")
            self.secure_mode = False
            return True
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.connected = False
        print("\nDisconnected from server")
    
    def _send_request(self, request):
        """Send request to server"""
        try:
            if not self.connected or not self.socket:
                print("\nNot connected to server")
                return False
            request_json = json.dumps(request)
            self.socket.send(request_json.encode('utf-8'))
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            print(f"\nConnection lost: {e}")
            self.connected = False
            return False
        except Exception as e:
            print(f"\nError sending request: {e}")
            return False
    
    def _send_secure_command(self, command):
        """Send command encrypted with AEAD"""
        try:
            if not self.secure_mode:
                # Fallback to regular send
                return self._send_request(command)
            
            # Convert command to JSON
            command_json = json.dumps(command)
            
            # Encrypt with AEAD
            encrypted = self.protocol.send_secure_message(
                self.secure_session_id,
                command_json,
                {'command': command.get('command')}
            )
            
            # Check if key rotation needed
            if encrypted.get('type') == 'KEY_ROTATION_REQUIRED':
                print("\n[Security] Key rotation needed - rotating keys...")
                self._rotate_keys()
                # Retry after rotation
                return self._send_secure_command(command)
            
            # Send encrypted message
            return self._send_request(encrypted)
            
        except Exception as e:
            print(f"\nError sending secure command: {e}")
            return False
    
    def _receive_response(self, timeout=15):
        """Receive response from server"""
        try:
            # Temporarily disable notification listener during request/response
            original_timeout = self.socket.gettimeout()
            self.socket.settimeout(timeout)
            data = self.socket.recv(32768)  # Increased for encrypted data
            self.socket.settimeout(original_timeout)
            
            if data:
                response = json.loads(data.decode('utf-8'))
                
                # Check if it's a notification
                if response.get('type') == 'NEW_MESSAGE':
                    print(f"\n\n[NOTIFICATION] New message from {response['from']}!")
                    print("Type '2' to view messages\n")
                    print("> ", end='', flush=True)
                    # After showing notification, receive the actual response
                    return self._receive_response(timeout)
                
                return response
            return None
        except socket.timeout:
            return {'status': 'error', 'message': 'Server timeout'}
        except Exception as e:
            return {'status': 'error', 'message': f'Error: {str(e)}'}
    
    def _receive_secure_response(self, timeout=15):
        """Receive and decrypt response (Lab 13: AEAD)"""
        try:
            encrypted_response = self._receive_response(timeout)
            
            if not encrypted_response or not self.secure_mode:
                return encrypted_response
            
            # Check if it's encrypted
            if encrypted_response.get('type') == 'SECURE_MESSAGE':
                # Decrypt with AEAD
                decrypted_json = self.protocol.receive_secure_message(
                    self.secure_session_id,
                    encrypted_response
                )
                return json.loads(decrypted_json)
            else:
                # Plain response (e.g., error)
                return encrypted_response
                
        except Exception as e:
            return {'status': 'error', 'message': f'Decryption error: {str(e)}'}
    
    def _rotate_keys(self):
        """Perform key rotation"""
        try:
            print("[Security] Initiating key rotation...")
            
            # Generate new ephemeral keys
            rotation_req = self.protocol.rotate_session_key(self.secure_session_id)
            
            # Send to server
            self._send_request(rotation_req)
            
            # Receive server's new keys
            rotation_resp = self._receive_response()
            
            if rotation_resp and rotation_resp.get('type') == 'KEY_ROTATION':
                # Complete rotation
                self.protocol.complete_key_rotation(self.secure_session_id, rotation_resp)
                
                print("Key rotation complete")
                print(f"New session key established")
                return True
            else:
                print("Key rotation failed")
                return False
                
        except Exception as e:
            print(f"Key rotation error: {e}")
            return False
    
    def _listen_for_notifications(self):
        """Listen for server notifications in background - DEPRECATED"""
        # This method is no longer used. Notifications are now handled
        # inline in _receive_response to avoid socket conflicts.
        pass
        # while self.running and self.username:
        #     try:
        #         self.socket.settimeout(1.0)
        #         data = self.socket.recv(4096)
        #         
        #         if data:
        #             try:
        #                 notification = json.loads(data.decode('utf-8'))
        #                 if notification.get('type') == 'NEW_MESSAGE':
        #                     print(f"\n\nNew message from {notification['from']}!")
        #                     print("Type '2' to view messages\n")
        #                     print("> ", end='', flush=True)
        #             except:
        #                 pass
        #     except socket.timeout:
        #         continue
        #     except:
        #         break
    
    def login(self):
        """Login to server"""
        print("\n--- LOGIN ---")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        request = {
            'command': 'LOGIN',
            'username': username,
            'password': password
        }
        
        # Use secure or regular mode
        send_func = self._send_secure_command if self.secure_mode else self._send_request
        recv_func = self._receive_secure_response if self.secure_mode else self._receive_response
        
        if send_func(request):
            response = recv_func()
            
            if response and response['status'] == 'success':
                self.username = username
                self.session_id = response['session_id']
                
                if self.secure_mode:
                    print(f"\n{response['message']} (Secure Mode)")
                    print(f"Welcome, {self.username}!")
                    print(f"\n[Security] Logged in with:")
                else:
                    print(f"\n{response['message']}")
                    print(f"Welcome, {self.username}!")
                
                # Notifications are now handled inline in _receive_response
                
                return True
            else:
                msg = response.get('message') if isinstance(response, dict) else 'Login failed'
                print(f"\n{msg}")
                return False
        
        return False
    
    def register(self):
        """Register new user"""
        print("\n--- REGISTER ---")
        username = input("Username: ").strip()
        password = input("Password (min 6 chars): ").strip()
        email = input("Email (optional): ").strip()
        
        request = {
            'command': 'REGISTER',
            'username': username,
            'password': password,
            'email': email
        }
        
        # Use secure or regular mode
        send_func = self._send_secure_command if self.secure_mode else self._send_request
        recv_func = self._receive_secure_response if self.secure_mode else self._receive_response
        
        if send_func(request):
            response = recv_func()
            
            if response and response['status'] == 'success':
                print(f"\n{response['message']}")
                if 'key_info' in response:
                    print(f"\n  ElGamal Key Generated:")
                    print(f"  - Prime (p): {response['key_info']['p']}")
                    print(f"  - Generator (g): {response['key_info']['g']}")
                    print(f"  - Public key: {response['key_info']['public_key']}")
                return True
            else:
                msg = response.get('message') if isinstance(response, dict) else 'Registration failed'
                print(f"\n{msg}")
                return False
        
        return False
    
    def send_message(self):
        """Send encrypted message"""
        print("\n--- SEND MESSAGE ---")
        print("[Transport: Secure AEAD | Message: Choose Cipher Below]")
        
        request = {
            'command': 'GET_USERS',
            'username': self.username
        }
        
        # Use secure or regular mode
        send_func = self._send_secure_command if self.secure_mode else self._send_request
        recv_func = self._receive_secure_response if self.secure_mode else self._receive_response
        
        if send_func(request):
            response = recv_func()
            
            if response and response['status'] == 'success':
                users = response['users']
                online_users = response['online_users']
                
                if not users:
                    print("\nNo other users registered")
                    return
                
                print(f"\nAvailable users:")
                for user in users:
                    status = "* online" if user in online_users else "X offline"
                    print(f"  - {user} ({status})")
                
                receiver = input("\nReceiver: ").strip()
                
                if receiver not in users:
                    print(f"\nUser '{receiver}' not found")
                    return
                
                message = input("Message: ").strip()
                
                if not message:
                    print("\nMessage cannot be empty")
                    return
                
                # Combined mode: Always show cipher selection
                print("\n--- SELECT MESSAGE ENCRYPTION (Educational Layer) ---")
                print("1. Caesar Cipher")
                print("2. Vigenère Cipher")
                print("3. XOR Stream Cipher")
                print("4. Mini Block Cipher")
                
                choice = input("\nChoice (1-4): ").strip()
                
                encryption_method = None
                encryption_params = {}
                
                if choice == '1':
                    shift = input("Shift value (default 3): ").strip()
                    encryption_method = 'Caesar'
                    encryption_params['shift'] = int(shift) if shift else 3
                
                elif choice == '2':
                    key = input("Vigenère key: ").strip()
                    if not key:
                        print("Key required")
                        return
                    encryption_method = 'Vigenere'
                    encryption_params['key'] = key
                
                elif choice == '3':
                    key = input("XOR key (optional, press Enter for random): ").strip()
                    encryption_method = 'XOR'
                    if key:
                        encryption_params['key'] = key
                
                elif choice == '4':
                    key = input("Block key (optional, press Enter for random): ").strip()
                    encryption_method = 'Block'
                    if key:
                        encryption_params['key'] = key
                
                else:
                    print("\nInvalid choice")
                    return
                
                request = {
                    'command': 'SEND_MESSAGE',
                    'sender': self.username,
                    'receiver': receiver,
                    'plaintext': message,
                    'encryption_method': encryption_method,
                    'encryption_params': encryption_params
                }
                
                if send_func(request):
                    response = recv_func(timeout=15)
                    
                    if response and response['status'] == 'success':
                        print(f"\nMessage sent successfully!")
                        print(f"Block #{response['block_index']}")
                        print(f"Block hash: {response['block_hash'][:32]}...")
                        print(f"Message hash: {response['message_hash'][:32]}...")
                        
                        print(f"\n[Security] Two-Layer Encryption Applied:")
                        print(f"Layer 1 (Transport): AEAD with DH session key (Labs 12-13)")
                        print(f"Layer 2 (Message): {encryption_method} cipher")
                        
                        if 'encryption_params' in response:
                            params = response['encryption_params']
                            if 'key_hex' in params:
                                print(f"\nSAVE THIS KEY FOR DECRYPTION:")
                                print(f"   Key (hex): {params['key_hex']}")
                    else:
                        msg = response.get('message') if isinstance(response, dict) else 'Failed to send'
                        print(f"\n{msg}")
    
    def view_messages(self):
        """View received messages"""
        print("\n--- YOUR MESSAGES ---")
        
        request = {
            'command': 'GET_MESSAGES',
            'username': self.username
        }
        
        if self._send_request(request):
            response = self._receive_response()
            
            if response and response['status'] == 'success':
                messages = response['messages']
                
                if not messages:
                    print("\nNo messages found.")
                    return
                
                print(f"\nFound {len(messages)} message(s):\n")
                
                for i, msg in enumerate(messages, 1):
                    print(f"{'-'*60}")
                    print(f"Message #{i} (Block #{msg['block_index']})")
                    print(f"From: {msg['sender']}")
                    print(f"To: {msg['receiver']}")
                    print(f"Timestamp: {msg['timestamp']}")
                    print(f"Encryption: {msg['encryption_method']}")
                    print(f"Ciphertext: {msg['ciphertext'][:50]}...")
                    print(f"Hash: {msg['message_hash'][:32]}...")
                    
                    if msg['receiver'] == self.username:
                        decrypt = input("\nDecrypt this message? (y/n): ").strip().lower()
                        if decrypt == 'y':
                            self._decrypt_message(msg)
                    print()
            else:
                msg = response.get('message') if isinstance(response, dict) else 'Failed to get messages'
                print(f"\nError: {msg}")
    
    def _decrypt_message(self, message_data):
        """Decrypt a message"""
        encryption_method = message_data['encryption_method']
        ciphertext = message_data['ciphertext']
        original_hash = message_data['message_hash']
        
        print(f"\n[Decrypting with {encryption_method}]")
        
        try:
            plaintext = None
            
            if encryption_method == 'Caesar':
                shift = int(input("Enter shift value used: ") or "3")
                cipher = CaesarCipher(shift=shift)
                plaintext = cipher.decrypt(ciphertext)
            
            elif encryption_method == 'Vigenere':
                key = input("Enter Vigenère key used: ").strip()
                cipher = VigenereCipher(key=key)
                plaintext = cipher.decrypt(ciphertext)
            
            elif encryption_method == 'XOR':
                key_hex = input("Enter XOR key (hex): ").strip()
                cipher = XORStreamCipher()
                cipher.set_key_from_hex(key_hex)
                plaintext = cipher.decrypt(ciphertext)
            
            elif encryption_method == 'Block':
                key_hex = input("Enter block cipher key (hex): ").strip()
                cipher = MiniBlockCipher()
                cipher.key = bytes.fromhex(key_hex)
                plaintext = cipher.decrypt(ciphertext)
            
            else:
                print("Unknown encryption method")
                return
            
            if plaintext:
                print(f"\nDecrypted message: {plaintext}")
                
                print("\n[Verifying message integrity...]")
                is_valid, computed_hash = MessageIntegrity.verify_hash(plaintext, original_hash)
                
                if is_valid:
                    print("Message integrity verified! Hash matches.")
                else:
                    print("WARNING: Message integrity check failed!")
                    print(f"Expected: {original_hash[:32]}...")
                    print(f"Computed: {computed_hash[:32]}...")
        
        except Exception as e:
            print(f"Decryption failed: {e}")
    
    def view_blockchain(self):
        """View blockchain"""
        print("\n--- BLOCKCHAIN EXPLORER ---")
        
        request = {'command': 'GET_BLOCKCHAIN'}
        
        if self._send_request(request):
            response = self._receive_response()
            
            if response and response['status'] == 'success':
                blocks = response['blocks']
                print(f"\nTotal blocks: {len(blocks)}\n")
                
                for block in blocks:
                    print(f"{'='*60}")
                    print(f"Block #{block['index']}")
                    print(f"Timestamp: {block['timestamp']}")
                    print(f"Previous Hash: {block['previous_hash'][:32]}...")
                    print(f"Block Hash: {block['hash']}")
                    print(f"Nonce: {block['nonce']}")
                    
                    if block['index'] > 0:
                        data = block['data']
                        print(f"\nMessage Data:")
                        print(f"Sender: {data['sender']}")
                        print(f"Receiver: {data['receiver']}")
                        print(f"Method: {data['encryption_method']}")
                    print()
            else:
                print(f"\nFailed to get blockchain")
    
    def verify_blockchain(self):
        """Verify blockchain integrity"""
        print("\n--- BLOCKCHAIN VERIFICATION ---")
        
        request = {'command': 'VERIFY_BLOCKCHAIN'}
        
        if self._send_request(request):
            response = self._receive_response()
            
            if response and response['status'] == 'success':
                is_valid = response['is_valid']
                message = response['message']
                chain_length = response['chain_length']
                
                if is_valid:
                    print(f"\n{message}")
                    print(f"All {chain_length} blocks verified")
                    print("Chain integrity: INTACT")
                else:
                    print(f"\n{message}")
                    print("Chain integrity: COMPROMISED")
            else:
                print(f"\nVerification failed")
    
    def display_banner(self):
        """Display client banner"""
        print("\n" + "="*60)
        print(" "*12 + "SECURE MESSAGING CLIENT")
        print("="*60 + "\n")
    
    def display_menu(self):
        """Display menu"""
        print(f"\n[Logged in as: {self.username} COMBINED MODE]")
        print("[Transport: Secure Protocol | Message: Classical Ciphers]")
        
        print("\n--- MENU ---")
        print("1. Send Message (Classical Cipher over Secure Transport)")
        print("2. View Messages")
        print("3. View Blockchain")
        print("4. Verify Blockchain")
        print("5. Manual Key Rotation (Lab 14)")
        print("6. Logout")
        print("7. Exit")
    
    def run(self):
        """Run client application"""
        self.display_banner()
        
        if not self.connect():
            return
        
        while True:
            print("\n1. Login")
            print("2. Register")
            print("3. Exit")
            
            choice = input("\nChoice: ").strip()
            
            if choice == '1':
                if self.login():
                    break
            elif choice == '2':
                self.register()
            elif choice == '3':
                self.disconnect()
                return
            else:
                print("\nInvalid choice")
        
        while self.running:
            try:
                self.display_menu()
                choice = input("\nChoice > ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.view_messages()
                elif choice == '3':
                    self.view_blockchain()
                elif choice == '4':
                    self.verify_blockchain()
                elif choice == '5':
                    print("\n[Security] Manually rotating keys...")
                    self._rotate_keys()
                elif choice == '6':
                    print("\nLogging out...")
                    self.disconnect()
                    break
                elif choice == '7':
                    print("\nExiting...")
                    self.disconnect()
                    break
                else:
                    print("\nInvalid choice")
            
            except KeyboardInterrupt:
                print("\n\nInterrupted. Logging out...")
                self.disconnect()
                break
            except Exception as e:
                print(f"\nError: {e}")


def main():
    """Entry point"""
    client = MessageClient(host='127.0.0.1', port=5555)
    
    try:
        client.run()
    except Exception as e:
        print(f"\nClient error: {e}")
    finally:
        if client.connected:
            client.disconnect()

if __name__ == "__main__":
    main()
