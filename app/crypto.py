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
    """
    Implementation of Shamir's Secret Sharing scheme with chunking for secrets of any length.
    
    This implementation splits secrets into chunks to avoid the prime modulus
    limitation, allowing for arbitrarily long secrets to be shared securely.
    """
    
    # Maximum bytes per chunk to stay safely under the prime modulus
    # Using 30 bytes (240 bits) for a 256-bit prime
    MAX_CHUNK_BYTES = 30
    
    # Prime number (slightly larger than 2^256)
    PRIME = 2**256 + 297
    
    @staticmethod
    def _evaluate_polynomial(coefficients, x, prime):
        """Evaluate a polynomial at point x."""
        result = 0
        # Evaluate using Horner's method
        for coefficient in reversed(coefficients):
            result = (result * x + coefficient) % prime
        return result
    
    @staticmethod
    def _mod_inverse(k, prime):
        """Calculate the modular multiplicative inverse."""
        # Extended Euclidean Algorithm
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = prime, k
        
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        
        # Make sure old_s > 0
        return old_s % prime
    
    @staticmethod
    def _lagrange_interpolation(x_values, y_values, x, prime):
        """
        Lagrange interpolation to find f(x) given points (x_values, y_values).
        """
        k = len(x_values)
        result = 0
        
        for i in range(k):
            numerator = 1
            denominator = 1
            
            for j in range(k):
                if i == j:
                    continue
                
                numerator = (numerator * (x - x_values[j])) % prime
                denominator = (denominator * (x_values[i] - x_values[j])) % prime
            
            # Compute the Lagrange basis polynomial evaluated at x
            lagrange_basis = (numerator * ShamirSecretSharing._mod_inverse(denominator, prime)) % prime
            
            # Add this term to the result
            result = (result + y_values[i] * lagrange_basis) % prime
        
        return result
    
    @staticmethod
    def _decode_bytes_to_string(byte_data):
        """
        Attempt to decode bytes to a string using multiple encodings and cleanup techniques.
        
        Args:
            byte_data: Bytes to decode
            
        Returns:
            str: Decoded string or error message
        """
        # Print detailed debug info
        print(f"Attempting to decode {len(byte_data)} bytes to string")
        print(f"First 20 bytes (hex): {byte_data[:20].hex()}")
        
        # Check for null bytes or strange control characters at the beginning
        clean_bytes = byte_data
        
        # Try stripping any leading bytes that might cause issues
        for unwanted in [b'\x00', b'\x20']:  # Null byte and space
            if clean_bytes.startswith(unwanted):
                clean_bytes = clean_bytes.lstrip(unwanted)
                print(f"Stripped leading bytes, new length: {len(clean_bytes)}")
        
        # Try multiple encodings
        encoding_attempts = ['utf-8', 'latin-1', 'ascii', 'iso-8859-1', 'cp1252']
        
        for encoding in encoding_attempts:
            try:
                result = clean_bytes.decode(encoding)
                print(f"Successfully decoded with {encoding}")
                
                # Check for gibberish - if over 20% of characters are non-printable, try another encoding
                import string
                printable = set(string.printable)
                non_printable_count = sum(1 for c in result if c not in printable)
                if non_printable_count > len(result) * 0.2:
                    print(f"Text appears to be gibberish ({non_printable_count}/{len(result)} non-printable chars)")
                    continue
                    
                return result
            except UnicodeDecodeError:
                print(f"Failed to decode with {encoding}")
        
        # If all standard decodings fail, try a binary-safe encoding as last resort
        try:
            # Interpret as raw bytes, replace non-printable with placeholders
            result = clean_bytes.decode('latin-1', errors='replace')
            print("Using latin-1 with replacement as last resort")
            return result
        except:
            # Absolute last resort - hex representation
            return f"BINARY:{clean_bytes.hex()}"
    
    @staticmethod
    def create_shares(secret, n, t):
        """
        Split a secret into n shares, where at least t shares are needed to
        reconstruct the secret.
        
        This implementation breaks the secret into chunks to handle secrets of any length.
        
        Args:
            secret (str): The secret to be shared
            n (int): The number of shares to create
            t (int): The threshold (minimum shares needed to reconstruct)
            
        Returns:
            list: A list of (index, share) tuples
        """
        if t > n:
            raise ValueError("Threshold cannot be greater than the number of shares")
        
        # Convert the secret to bytes
        if isinstance(secret, str):
            secret_bytes = secret.encode('utf-8')
        else:
            secret_bytes = secret
        
        # For empty or very short secrets, add a single chunk
        if not secret_bytes:
            secret_bytes = b'\x00'  # Use a null byte for empty secrets
        
        # Split the secret into chunks
        chunks = []
        for i in range(0, len(secret_bytes), ShamirSecretSharing.MAX_CHUNK_BYTES):
            chunk = secret_bytes[i:i + ShamirSecretSharing.MAX_CHUNK_BYTES]
            chunks.append(chunk)
        
        # Import secrets module for secure random number generation
        import secrets as secrets_module
        
        # Create separate polynomials for each chunk
        chunk_shares = []
        for chunk_idx, chunk in enumerate(chunks):
            # Convert chunk to an integer
            chunk_int = int.from_bytes(chunk, byteorder='big')
            
            # Generate a random polynomial with the chunk as the constant term
            coefficients = [chunk_int]
            for _ in range(t - 1):
                coefficients.append(secrets_module.randbelow(ShamirSecretSharing.PRIME))
            
            # Generate the shares for this chunk
            chunk_share_values = []
            for i in range(1, n + 1):  # Use indices 1 to n (not 0)
                # Evaluate the polynomial at point i
                y = ShamirSecretSharing._evaluate_polynomial(
                    coefficients, i, ShamirSecretSharing.PRIME
                )
                chunk_share_values.append((i, y))
            
            chunk_shares.append(chunk_share_values)
        
        # Combine the chunk shares into final shares
        # Format: SSv2:<num_chunks>:<chunk1_value>:<chunk2_value>:...
        shares = []
        for i in range(n):
            share_str = f"SSv2:{len(chunks)}"
            for chunk_idx in range(len(chunks)):
                chunk_value = chunk_shares[chunk_idx][i][1]
                share_str += f":{chunk_value:x}"
            
            shares.append((i + 1, share_str))
        
        return shares
    
    @staticmethod
    def reconstruct_secret(shares, t):
        """
        Reconstruct the secret from at least t shares.
        
        Args:
            shares (list): A list of (index, share) tuples
            t (int): The threshold (minimum shares needed)
            
        Returns:
            str: The reconstructed secret
        """
        if len(shares) < t:
            raise ValueError(f"Need at least {t} shares to reconstruct, but only {len(shares)} provided")
        
        # Debug info
        print(f"Reconstructing secret with {len(shares)} shares (threshold={t})")
        for i, (idx, share) in enumerate(shares[:t]):
            if isinstance(share, str):
                print(f"Share {i}: index={idx}, format={'SSv2' if share.startswith('SSv2:') else 'SS' if share.startswith('SS') else 'other'}, length={len(share)}")
            else:
                print(f"Share {i}: index={idx}, type={type(share)}")
        
        # Find the first share to use as a template
        template_share = shares[0][1]
        
        # Parse the v2 format
        parts = template_share.split(':')
        if len(parts) < 3 or not template_share.startswith('SSv2:'):
            raise ValueError(f"Invalid share format: {template_share[:30]}...")
        
        # Extract the number of chunks
        num_chunks = int(parts[1])
        print(f"Found share with {num_chunks} chunks")
        
        # Reconstruct each chunk
        chunk_bytes = []
        
        for chunk_idx in range(num_chunks):
            # Position in parts list (skip prefix and num_chunks)
            part_idx = chunk_idx + 2
            
            # Collect x and y values for this chunk from all shares
            x_values = []
            y_values = []
            
            for share_idx, (x, share) in enumerate(shares[:t]):
                share_parts = share.split(':')
                if part_idx < len(share_parts):
                    try:
                        # Check if the share has the same format
                        if not share.startswith('SSv2:'):
                            print(f"WARNING: Share {share_idx} has incorrect format")
                            continue
                        
                        chunk_value = int(share_parts[part_idx], 16)
                        x_values.append(x)
                        y_values.append(chunk_value)
                    except ValueError as e:
                        print(f"Error parsing chunk value from share {share_idx}, chunk {chunk_idx}: {e}")
                        continue
                else:
                    print(f"WARNING: Share {share_idx} missing chunk {chunk_idx}")
            
            # Check if we have enough values for reconstruction
            if len(x_values) < t:
                raise ValueError(f"Not enough valid shares for chunk {chunk_idx}, have {len(x_values)}, need {t}")
            
            # Reconstruct the chunk using Lagrange interpolation
            chunk_int = ShamirSecretSharing._lagrange_interpolation(
                x_values, y_values, 0, ShamirSecretSharing.PRIME
            )
            
            # Convert back to bytes with proper length calculation
            try:
                # For regular chunks, use the max chunk size
                if chunk_idx < num_chunks - 1:
                    byte_length = ShamirSecretSharing.MAX_CHUNK_BYTES
                else:
                    # For the last chunk, calculate based on bit length
                    byte_length = max(1, (chunk_int.bit_length() + 7) // 8)
                
                # Debug info
                print(f"Chunk {chunk_idx}: int value bits={chunk_int.bit_length()}, calculated bytes={byte_length}")
                
                # Safety check to avoid overflow
                max_safe_length = (chunk_int.bit_length() + 7) // 8
                if byte_length > max_safe_length:
                    print(f"WARNING: Adjusting byte length from {byte_length} to {max_safe_length}")
                    byte_length = max_safe_length
                
                chunk_bytes.append(chunk_int.to_bytes(byte_length, byteorder='big'))
            except OverflowError as e:
                # If conversion fails, try with the exact bit length
                print(f"Overflow when converting chunk {chunk_idx}, trying exact bit length")
                exact_bytes = (chunk_int.bit_length() + 7) // 8
                try:
                    chunk_bytes.append(chunk_int.to_bytes(exact_bytes, byteorder='big'))
                except Exception as inner_e:
                    # If still failing, try reducing length
                    print(f"Still failing with exact bytes, error: {inner_e}")
                    for attempt in range(exact_bytes-1, 0, -1):
                        try:
                            print(f"Trying with {attempt} bytes")
                            chunk_bytes.append(chunk_int.to_bytes(attempt, byteorder='big'))
                            break
                        except:
                            continue
                    else:
                        raise ValueError(f"Could not convert chunk {chunk_idx} to bytes")
        
        # Combine all chunks
        secret_bytes = b''.join(chunk_bytes)
        
        # Handle special case for empty secret
        if secret_bytes == b'\x00' and num_chunks == 1:
            return ""
        
        # Use our improved decoding function
        return ShamirSecretSharing._decode_bytes_to_string(secret_bytes)