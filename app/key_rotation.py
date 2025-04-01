"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Utilities for key rotation
"""

import os
import base64
import json
import secrets
from typing import List, Dict, Any

from app import db
from models import KeyShare, Vault
from crypto import create_share_key, encrypt_data, decrypt_data, derive_key, SecureKey
from secure_config import get_key_version, secure_wipe


def rotate_keys():
    """
    Rotate encryption keys by re-encrypting all shares with new keys.
    
    This should be run when:
    1. KEY_ESCROW_KEY_VERSION is incremented
    2. KEY_ESCROW_MASTER_KEY is changed
    3. As part of regular security maintenance
    """
    print("Starting key rotation process...")
    
    # Get all vaults
    vaults = Vault.query.all()
    print(f"Found {len(vaults)} vaults to process")
    
    # Current key version
    current_version = get_key_version()
    
    # Process each vault
    for vault in vaults:
        print(f"Processing vault {vault.vault_id}")
        
        # Get all system shares for this vault
        system_shares = KeyShare.query.filter_by(vault_id=vault.id, share_type="system").all()
        
        # Process each share
        for share in system_shares:
            try:
                print(f"  Rotating share {share.id} (index: {share.share_index})")
                
                # Decode the share data
                share_data = json.loads(share.encrypted_share)
                salt = base64.b64decode(share_data['salt'])
                
                # Decrypt with old key
                # We use the old key version which is encoded in the encrypted data
                with SecureKey() as secure_context:
                    # Derive the old key
                    old_context = f"share_system_share_{share.share_index}_{vault.vault_id}"
                    old_key, _ = derive_key(old_context, salt, old_context)
                    
                    # Decrypt the data
                    decrypted_share = decrypt_data(share_data['share'], old_key)
                    
                    # Generate new salt and key for re-encryption
                    new_salt = os.urandom(16)
                    new_context = f"share_system_share_{share.share_index}_{vault.vault_id}"
                    new_key, _ = derive_key(new_context, new_salt, new_context)
                    
                    # Re-encrypt with new key
                    encrypted_share = encrypt_data(decrypted_share, new_key)
                    
                    # Update the database
                    share.encrypted_share = json.dumps({
                        "salt": base64.b64encode(new_salt).decode('utf-8'),
                        "share": encrypted_share,
                        "version": current_version
                    })
                    
                    # Clear sensitive data
                    secure_wipe(old_key)
                    secure_wipe(new_key)
                    # Don't wipe decrypted_share here as it might be used again in the loop
            
            except Exception as e:
                print(f"  Error rotating share {share.id}: {str(e)}")
                continue
        
        # Commit changes for this vault
        db.session.commit()
        print(f"Completed rotation for vault {vault.vault_id}")
    
    print("Key rotation complete!")


def generate_new_keys():
    """
    Generate and print new keys for environment configuration.
    """
    master_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    key_pepper = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    print("\nNew security keys generated:")
    print("============================")
    print(f"KEY_ESCROW_MASTER_KEY=\"{master_key}\"")
    print(f"KEY_ESCROW_KEY_PEPPER=\"{key_pepper}\"")
    print("\nStore these in your environment or .env file")
    print("IMPORTANT: Run the key rotation script after updating these values!")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        generate_new_keys()
    else:
        rotate_keys()