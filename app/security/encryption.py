"""
Data Encryption Module for sensitive health data
Uses Fernet symmetric encryption (AES-128 in CBC mode)
"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import os

class DataEncryption:
    """
    Encrypt and decrypt sensitive data at rest
    """
    
    def __init__(self, secret_key=None):
        """
        Initialize encryption with key
        
        Args:
            secret_key: String key for encryption. If None, uses env var ENCRYPTION_KEY
        """
        if secret_key is None:
            secret_key = os.environ.get('ENCRYPTION_KEY', 'default-encryption-key-change-in-production')
        
        # Derive a proper Fernet key from the secret key
        self.fernet_key = self._derive_key(secret_key)
        self.cipher = Fernet(self.fernet_key)
    
    @staticmethod
    def _derive_key(password):
        """
        Derive a Fernet key from password using PBKDF2
        """
        # Use a fixed salt for deterministic key derivation
        # In production, consider using a per-field salt stored alongside data
        salt = b'stroke_app_salt_2024'
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext data
        
        Args:
            plaintext: String or bytes to encrypt
        
        Returns:
            Encrypted data as string
        """
        if plaintext is None:
            return None
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        encrypted = self.cipher.encrypt(plaintext)
        return base64.urlsafe_b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_text):
        """
        Decrypt encrypted data
        
        Args:
            encrypted_text: Encrypted string
        
        Returns:
            Decrypted plaintext as string
        """
        if encrypted_text is None:
            return None
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            # Log error but don't expose details
            print(f"Decryption error: {type(e).__name__}")
            return None
    
    @staticmethod
    def generate_key():
        """
        Generate a new Fernet key for use as ENCRYPTION_KEY
        
        Returns:
            Base64-encoded key string
        """
        return Fernet.generate_key().decode('utf-8')


# Singleton instance
_encryptor = None

def get_encryptor():
    """
    Get singleton encryption instance
    """
    global _encryptor
    if _encryptor is None:
        _encryptor = DataEncryption()
    return _encryptor


def encrypt_sensitive_data(data):
    """
    Quick function to encrypt sensitive data
    """
    return get_encryptor().encrypt(data)


def decrypt_sensitive_data(encrypted_data):
    """
    Quick function to decrypt sensitive data
    """
    return get_encryptor().decrypt(encrypted_data)
