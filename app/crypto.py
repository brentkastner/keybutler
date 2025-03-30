"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Cryptographic utilities for secure key management
"""

import base64
import os
import secrets
from typing import List, Tuple

import nacl.secret
import nacl.utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a password using PBKDF2.
    
    Args:
        password: The password to derive the key from
        salt: Optional salt bytes. If None, a random salt will be generated
        
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt


def encrypt_data(data: str, key: bytes) -> str:
    """
    Encrypt data using NaCl's SecretBox (XSalsa20-Poly1305).
    
    Args:
        data: The string data to encrypt
        key: 32-byte encryption key
        
    Returns:
        Base64-encoded encrypted data
    """
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(data.encode(), nonce)
    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_data(encrypted_data: str, key: bytes) -> str:
    """
    Decrypt data using NaCl's SecretBox.
    
    Args:
        encrypted_data: Base64-encoded encrypted data
        key: 32-byte encryption key
        
    Returns:
        Decrypted string
    """
    box = nacl.secret.SecretBox(key)
    decrypted = box.decrypt(base64.b64decode(encrypted_data))
    return decrypted.decode('utf-8')


class ShamirSecretSharing:
    """Implementation of Shamir's Secret Sharing threshold scheme."""
    
    @staticmethod
    def _evaluate_polynomial(coefficients: List[int], x: int, prime: int) -> int:
        """Evaluate a polynomial at point x."""
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * x + coefficient) % prime
        return result
    
    @staticmethod
    def _mod_inverse(k: int, prime: int) -> int:
        """Calculate the modular multiplicative inverse."""
        k = k % prime
        if k < 0:
            k += prime
        # Extended Euclidean Algorithm
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = prime, k
        
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        
        return old_s % prime
    
    @staticmethod
    def create_shares(secret: str, n: int, t: int) -> List[Tuple[int, str]]:
        """
        Split a secret into n shares, requiring t shares to reconstruct.
        
        Args:
            secret: The secret string to share
            n: Number of shares to create
            t: Threshold (minimum shares needed to reconstruct)
            
        Returns:
            List of (index, share_value) tuples
        """
        if t > n:
            raise ValueError("Threshold t cannot be greater than the number of shares n")
        
        # Use a large prime from the Mersenne family
        prime = 2**521 - 1  # A Mersenne prime
        
        # Convert secret to an integer
        secret_bytes = secret.encode()
        secret_int = int.from_bytes(secret_bytes, byteorder='big')
        
        # Generate random coefficients for the polynomial
        # The constant term is the secret, other coefficients are random
        coefficients = [secret_int]
        for _ in range(t - 1):
            coefficients.append(secrets.randbelow(prime))
        
        # Generate the shares by evaluating the polynomial at different points
        shares = []
        for i in range(1, n + 1):
            y = ShamirSecretSharing._evaluate_polynomial(coefficients, i, prime)
            shares.append((i, format(y, 'x')))  # Store as hex string
        
        return shares
    
    @staticmethod
    def reconstruct_secret(shares: List[Tuple[int, str]], t: int) -> str:
        """
        Reconstruct the secret from t shares using Lagrange interpolation.
        
        Args:
            shares: List of (index, share_value) tuples
            t: Threshold (minimum shares needed to reconstruct)
            
        Returns:
            The reconstructed secret string
        """
        if len(shares) < t:
            raise ValueError(f"Need at least {t} shares, got {len(shares)}")
        
        prime = 2**521 - 1  # Same prime as used in create_shares
        
        # Convert hex strings back to integers
        processed_shares = [(i, int(s, 16)) for i, s in shares]
        
        # Use Lagrange interpolation to reconstruct the secret
        secret = 0
        for i, share_i in processed_shares[:t]:
            numerator = 1
            denominator = 1
            for j, _ in processed_shares[:t]:
                if i != j:
                    numerator = (numerator * j) % prime
                    denominator = (denominator * (j - i)) % prime
            
            # Calculate the Lagrange basis polynomial
            lagrange = (share_i * numerator * ShamirSecretSharing._mod_inverse(denominator, prime)) % prime
            secret = (secret + lagrange) % prime
        
        # Convert the integer back to bytes and then to string
        # Calculate the required number of bytes
        byte_length = (secret.bit_length() + 7) // 8
        secret_bytes = secret.to_bytes(byte_length, byteorder='big')
        
        try:
            return secret_bytes.decode()
        except UnicodeDecodeError:
            # This can happen if the shares are incorrect
            raise ValueError("Failed to reconstruct the secret. The shares may be incorrect.")