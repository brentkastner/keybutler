"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Secure configuration for key management
"""

import os
import secrets
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# Environment variable names
ENV_MASTER_KEY = "KEY_ESCROW_MASTER_KEY"
ENV_KEY_PEPPER = "KEY_ESCROW_KEY_PEPPER"
ENV_PBKDF2_ITERATIONS = "KEY_ESCROW_PBKDF2_ITERATIONS"
ENV_KEY_VERSION = "KEY_ESCROW_KEY_VERSION"


def get_master_key():
    """
    Get the master key from environment variables or generate one if not set.
    In production, this should always be set via environment variables.
    
    Returns:
        bytes: The master key bytes
    """
    master_key = os.environ.get(ENV_MASTER_KEY)
    
    if not master_key:
        # For development only - in production this should error out
        if os.environ.get("FLASK_ENV") == "production":
            raise ValueError(f"Missing {ENV_MASTER_KEY} environment variable in production")
            
        # Generate and print a warning for development
        master_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        print(f"WARNING: No {ENV_MASTER_KEY} found. Generated temporary key: {master_key}")
        print("Set this in your environment for consistent encryption/decryption")
        
        # Set it for the current process
        os.environ[ENV_MASTER_KEY] = master_key
    
    # Decode from base64
    return base64.b64decode(master_key)


def get_key_pepper():
    """
    Get the pepper (server-side secret salt) from environment or generate one.
    
    Returns:
        bytes: The pepper bytes
    """
    pepper = os.environ.get(ENV_KEY_PEPPER)
    
    if not pepper:
        # For development only
        if os.environ.get("FLASK_ENV") == "production":
            raise ValueError(f"Missing {ENV_KEY_PEPPER} environment variable in production")
            
        # Generate and set for the process
        pepper = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        print(f"WARNING: No {ENV_KEY_PEPPER} found. Generated temporary pepper.")
        
        # Set it for the current process
        os.environ[ENV_KEY_PEPPER] = pepper
    
    # Decode from base64
    return base64.b64decode(pepper)


def get_pbkdf2_iterations():
    """
    Get the number of PBKDF2 iterations to use.
    
    Returns:
        int: The number of iterations
    """
    iterations = os.environ.get(ENV_PBKDF2_ITERATIONS)
    if iterations:
        return int(iterations)
    
    # Default to a secure value
    return 600000


def get_key_version():
    """
    Get the current key version for key rotation.
    
    Returns:
        int: The key version number
    """
    version = os.environ.get(ENV_KEY_VERSION)
    if version:
        return int(version)
    
    # Default to version 1
    return 1


# Secure memory wipe function
def secure_wipe(data):
    """
    Securely wipe a bytes, bytearray, or string object from memory.
    
    Args:
        data: The data to wipe (bytes, bytearray, or string)
    """
    import ctypes
    
    if data is None:
        return
    
    # Handle different data types
    if isinstance(data, str):
        # Convert string to bytearray
        data_array = bytearray(data.encode('utf-8'))
    elif isinstance(data, bytes):
        # Convert immutable bytes to bytearray
        data_array = bytearray(data)
    elif isinstance(data, bytearray):
        data_array = data
    else:
        # Not a type we can wipe
        return
    
    length = len(data_array)
    if length == 0:
        return
    
    # Get pointer to the memory
    addr = ctypes.addressof((ctypes.c_char * length).from_buffer(data_array))
    
    # Overwrite with zeros
    ctypes.memset(addr, 0, length)