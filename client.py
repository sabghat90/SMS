"""
Secure Messaging System - Client
Network client for connecting to the messaging server
Run this in separate terminals for different users
"""

import socket
import json
import threading
from src.core.classical_ciphers import CaesarCipher, VigenereCipher
from src.core.modern_ciphers import XORStreamCipher, MiniBlockCipher
from src.core.hashing import MessageIntegrity


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
        
        self.notification_thread = None
    
    def connect(self):
        """Connect to server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.running = True
            print(f"\nConnected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"\nCould not connect to server: {e}")
            print(f"Make sure the server is running!")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        
        if self.connected and self.username:
            self._send_request({'command': 'LOGOUT'})
        
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
    
    def _receive_response(self, timeout=5):
        """Receive response from server"""
        try:
            # Temporarily disable notification listener during request/response
            original_timeout = self.socket.gettimeout()
            self.socket.settimeout(timeout)
            data = self.socket.recv(4096)
            self.socket.settimeout(original_timeout)
            
            if data:
                response = json.loads(data.decode('utf-8'))
                return response
            return None
        except socket.timeout:
            return {'status': 'error', 'message': 'Server timeout'}
        except Exception as e:
            return {'status': 'error', 'message': f'Error: {str(e)}'}
    
    def _listen_for_notifications(self):
        """Listen for server notifications in background"""
        while self.running and self.username:
            try:
                self.socket.settimeout(1.0)
                data = self.socket.recv(4096)
                
                if data:
                    try:
                        notification = json.loads(data.decode('utf-8'))
                        if notification.get('type') == 'NEW_MESSAGE':
                            print(f"\n\nNew message from {notification['from']}!")
                            print("Type '2' to view messages\n")
                            print("> ", end='', flush=True)
                    except:
                        pass
            except socket.timeout:
                continue
            except:
                break
    
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
        
        if self._send_request(request):
            response = self._receive_response()
            
            if response and response['status'] == 'success':
                self.username = username
                self.session_id = response['session_id']
                print(f"\n{response['message']}")
                print(f"Welcome, {self.username}!")
                
                self.notification_thread = threading.Thread(
                    target=self._listen_for_notifications,
                    daemon=True
                )
                self.notification_thread.start()
                
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
        
        if self._send_request(request):
            response = self._receive_response()
            
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
        
        request = {
            'command': 'GET_USERS',
            'username': self.username
        }
        
        if self._send_request(request):
            response = self._receive_response()
            
            if response and response['status'] == 'success':
                users = response['users']
                online_users = response['online_users']
                
                if not users:
                    print("\nNo other users registered")
                    return
                
                print(f"\nAvailable users:")
                for user in users:
                    status = "+ online" if user in online_users else "X offline"
                    print(f"  - {user} ({status})")
                
                receiver = input("\nReceiver: ").strip()
                
                if receiver not in users:
                    print(f"\nUser '{receiver}' not found")
                    return
                
                message = input("Message: ").strip()
                
                if not message:
                    print("\nMessage cannot be empty")
                    return
                
                print("\n--- SELECT ENCRYPTION ---")
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
                
                if self._send_request(request):
                    response = self._receive_response(timeout=10)
                    
                    if response and response['status'] == 'success':
                        print(f"\nMessage sent successfully!")
                        print(f"Block #{response['block_index']}")
                        print(f"Block hash: {response['block_hash'][:32]}...")
                        print(f"Message hash: {response['message_hash'][:32]}...")
                        
                        if 'encryption_params' in response:
                            params = response['encryption_params']
                            if 'key_hex' in params:
                                print(f"\nSAVE THIS KEY FOR DECRYPTION:")
                                print(f"Key (hex): {params['key_hex']}")
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
        print(" "*15 + "SECURE MESSAGING CLIENT")
        print(" "*10 + "Multi-Terminal Messaging System")
        print("="*60 + "\n")
    
    def display_menu(self):
        """Display menu"""
        print(f"\n[Logged in as: {self.username}]")
        print("\n--- MENU ---")
        print("1. Send Message")
        print("2. View Messages")
        print("3. View Blockchain")
        print("4. Verify Blockchain")
        print("5. Logout")
        print("6. Exit")
    
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
                choice = input("\n> ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.view_messages()
                elif choice == '3':
                    self.view_blockchain()
                elif choice == '4':
                    self.verify_blockchain()
                elif choice == '5':
                    print("\nLogging out...")
                    self.disconnect()
                    break
                elif choice == '6':
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
