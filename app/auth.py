"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Authentication utilities including TOTP implementation and middleware
"""

import base64
import hashlib
import hmac
import time
from functools import wraps

from flask import jsonify, session


def generate_totp_secret() -> str:
    """
    Generate a secure TOTP secret compatible with standard authenticator apps.
    
    Returns:
        Base32-encoded TOTP secret string
    """
    import secrets
    # Generate 20 random bytes (160 bits) for the TOTP secret
    random_bytes = secrets.token_bytes(20)
    # Encode as base32 for use with TOTP apps
    return base64.b32encode(random_bytes).decode('utf-8')


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against a secret.
    
    This is a simplified TOTP implementation for the prototype.
    In production, use a well-tested library like pyotp.
    
    Args:
        secret: Base32-encoded TOTP secret
        code: 6-digit TOTP code to verify
        
    Returns:
        True if the code is valid, False otherwise
    """
    if not code or not code.isdigit() or len(code) != 6:
        return False
    
    # Get current time step (30-second intervals)
    now = int(time.time()) // 30
    
    # Check current time step and adjacent steps (30 seconds before and after)
    for delta in range(-1, 2):
        time_step = now + delta
        # Create the HMAC value
        hmac_digest = hmac.new(
            base64.b32decode(secret, casefold=True),
            time_step.to_bytes(8, byteorder='big'),
            hashlib.sha1
        ).digest()
        
        # Generate code using the TOTP algorithm
        offset = hmac_digest[-1] & 0x0F
        code_int = ((hmac_digest[offset] & 0x7F) << 24 |
                   (hmac_digest[offset + 1] & 0xFF) << 16 |
                   (hmac_digest[offset + 2] & 0xFF) << 8 |
                   (hmac_digest[offset + 3] & 0xFF))
        calculated_code = str(code_int % 10**6).zfill(6)
        
        if calculated_code == code:
            return True
    
    return False


def login_required(f):
    """
    Decorator for routes that require user login.
    Checks if user_id is in the session.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


def require_totp(f):
    """
    Decorator for routes that require TOTP verification.
    Must be used with login_required.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'totp_verified' not in session or not session['totp_verified']:
            return jsonify({"error": "TOTP verification required"}), 401
        return f(*args, **kwargs)
    return decorated_function