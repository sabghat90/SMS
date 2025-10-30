"""
Classical Ciphers Module
Lab 03 & Lab 04 Concepts: Caesar Cipher and Vigenère Cipher
"""


class CaesarCipher:
    """
    Caesar Cipher: Shifts each letter by a fixed number of positions
    Lab 03 Concept
    """
    
    def __init__(self, shift=3):
        self.shift = shift
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using Caesar cipher"""
        ciphertext = ""
        
        for char in plaintext:
            if char.isalpha():
                # Determine if uppercase or lowercase
                ascii_offset = ord('A') if char.isupper() else ord('a')
                # Shift character
                shifted = (ord(char) - ascii_offset + self.shift) % 26
                ciphertext += chr(shifted + ascii_offset)
            else:
                # Non-alphabetic characters remain unchanged
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Caesar cipher"""
        # Decryption is just encryption with negative shift
        original_shift = self.shift
        self.shift = -self.shift
        plaintext = self.encrypt(ciphertext)
        self.shift = original_shift
        return plaintext


class VigenereCipher:
    """
    Vigenère Cipher: Polyalphabetic substitution using a keyword
    Lab 04 Concept
    """
    
    def __init__(self, key):
        self.key = key.upper()
    
    def _extend_key(self, text_length):
        """Extend key to match text length"""
        extended_key = ""
        key_index = 0
        
        for i in range(text_length):
            extended_key += self.key[key_index % len(self.key)]
            key_index += 1
        
        return extended_key
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using Vigenère cipher"""
        ciphertext = ""
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                # Determine if uppercase or lowercase
                ascii_offset = ord('A') if char.isupper() else ord('a')
                
                # Get corresponding key character
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # Encrypt character
                shifted = (ord(char) - ascii_offset + key_shift) % 26
                ciphertext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                # Non-alphabetic characters remain unchanged
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Vigenère cipher"""
        plaintext = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                # Determine if uppercase or lowercase
                ascii_offset = ord('A') if char.isupper() else ord('a')
                
                # Get corresponding key character
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # Decrypt character
                shifted = (ord(char) - ascii_offset - key_shift) % 26
                plaintext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                # Non-alphabetic characters remain unchanged
                plaintext += char
        
        return plaintext


# Testing
if __name__ == "__main__":
    print("=== Classical Ciphers Module Tests ===\n")
    
    # Test Caesar Cipher
    print("1. Caesar Cipher (shift=3):")
    caesar = CaesarCipher(shift=3)
    plaintext = "Hello World"
    encrypted = caesar.encrypt(plaintext)
    decrypted = caesar.decrypt(encrypted)
    print(f"   Plaintext:  {plaintext}")
    print(f"   Encrypted:  {encrypted}")
    print(f"   Decrypted:  {decrypted}\n")
    
    # Test Vigenère Cipher
    print("2. Vigenère Cipher (key='SECRET'):")
    vigenere = VigenereCipher(key="SECRET")
    plaintext = "Attack at Dawn"
    encrypted = vigenere.encrypt(plaintext)
    decrypted = vigenere.decrypt(encrypted)
    print(f"   Plaintext:  {plaintext}")
    print(f"   Encrypted:  {encrypted}")
    print(f"   Decrypted:  {decrypted}\n")
    
    # Test with different key
    print("3. Vigenère Cipher (key='KEY'):")
    vigenere2 = VigenereCipher(key="KEY")
    plaintext = "CRYPTOGRAPHY"
    encrypted = vigenere2.encrypt(plaintext)
    decrypted = vigenere2.decrypt(encrypted)
    print(f"   Plaintext:  {plaintext}")
    print(f"   Encrypted:  {encrypted}")
    print(f"   Decrypted:  {decrypted}\n")
