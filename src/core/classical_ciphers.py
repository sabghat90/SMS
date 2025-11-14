"""
Classical Ciphers Module
Caesar Cipher and Vigenère Cipher
"""


class CaesarCipher:
    """
    Caesar Cipher: Shifts each letter by a fixed number of positions
    """
    
    def __init__(self, shift=3):
        self.shift = shift
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using Caesar cipher (converts to uppercase)"""
        ciphertext = ""
        
        for char in plaintext:
            if char.isalpha():
                char = char.upper()
                ascii_offset = ord('A')
                shifted = (ord(char) - ascii_offset + self.shift) % 26
                ciphertext += chr(shifted + ascii_offset)
            else:
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Caesar cipher"""
        original_shift = self.shift
        self.shift = -self.shift
        plaintext = self.encrypt(ciphertext)
        self.shift = original_shift
        return plaintext


class VigenereCipher:
    """
    Vigenère Cipher: Polyalphabetic substitution using a keyword
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
                ascii_offset = ord('A') if char.isupper() else ord('a')
                
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                shifted = (ord(char) - ascii_offset + key_shift) % 26
                ciphertext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext using Vigenère cipher"""
        plaintext = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                shifted = (ord(char) - ascii_offset - key_shift) % 26
                plaintext += chr(shifted + ascii_offset)
                
                key_index += 1
            else:
                plaintext += char
        
        return plaintext
