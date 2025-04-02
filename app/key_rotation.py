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
from crypto import create_share_key, encrypt_data, decrypt_data, SecureKey
from secure_config import get_key_version, secure_wipe

#TODO: Test key rotation
def rotate_keys(old_master_key=None):
    """
    Rotate encryption keys by re-encrypting all shares with new keys.
    
    Args:
        old_master_key: Optional previous master key when rotating master keys
    """
    print("Starting key rotation process...")
    
    # Get all vaults
    vaults = Vault.query.all()
    print(f"Found {len(vaults)} vaults to process")
    
    # Current key version
    old_version = get_key_version() - 1
    current_version = get_key_version()
    
    if old_version < 1:
        old_version = 1  # Minimum version
    
    print(f"Rotating from version {old_version} to {current_version}")
    
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
                
                # Determine which master key to use for decryption
                decryption_master_key = old_master_key if old_master_key else None
                
                # Get the version from the share data if available
                share_version = share_data.get('version', old_version)
                
                # Temporary store for sensitive data to ensure wiping
                sensitive_data = []
                
                try:
                    # Set up the environment for decryption using the appropriate key
                    if decryption_master_key:
                        # Temporarily override the environment master key
                        original_master_key = os.environ.get("KEY_ESCROW_MASTER_KEY")
                        os.environ["KEY_ESCROW_MASTER_KEY"] = decryption_master_key
                    
                    # For backwards compatibility with unversioned shares
                    if 'version' not in share_data:
                        # Use the original key derivation without versioning
                        share_key, _ = create_share_key(
                            share.share_index, 
                            vault.vault_id, 
                            "system_share", 
                            salt
                        )
                    else:
                        # Use versioned key derivation
                        # Set the version environment variable temporarily
                        original_version = os.environ.get("KEY_ESCROW_KEY_VERSION")
                        os.environ["KEY_ESCROW_KEY_VERSION"] = str(share_version)
                        
                        # Derive key with correct version
                        share_key, _ = create_share_key(
                            share.share_index, 
                            vault.vault_id, 
                            "system_share", 
                            salt
                        )
                        
                        # Restore original version
                        if original_version:
                            os.environ["KEY_ESCROW_KEY_VERSION"] = original_version
                        else:
                            os.environ.pop("KEY_ESCROW_KEY_VERSION")
                    
                    sensitive_data.append(share_key)
                    
                    # Decrypt the data with the appropriate key
                    decrypted_share = decrypt_data(share_data['share'], share_key)
                    sensitive_data.append(decrypted_share)
                    
                    # Restore the original master key if we changed it
                    if decryption_master_key:
                        if original_master_key:
                            os.environ["KEY_ESCROW_MASTER_KEY"] = original_master_key
                        else:
                            os.environ.pop("KEY_ESCROW_MASTER_KEY")
                    
                    # Generate new salt and key for re-encryption with current settings
                    new_salt = os.urandom(16)
                    
                    # Ensure current version is used for encryption
                    os.environ["KEY_ESCROW_KEY_VERSION"] = str(current_version)
                    
                    # Derive a new key for encryption
                    new_key, _ = create_share_key(
                        share.share_index, 
                        vault.vault_id, 
                        "system_share", 
                        new_salt
                    )
                    sensitive_data.append(new_key)
                    
                    # Re-encrypt with new key
                    encrypted_share = encrypt_data(decrypted_share, new_key)
                    
                    # Update the database
                    share.encrypted_share = json.dumps({
                        "salt": base64.b64encode(new_salt).decode('utf-8'),
                        "share": encrypted_share,
                        "version": current_version
                    })
                    
                finally:
                    # Clear all sensitive data
                    for data in sensitive_data:
                        secure_wipe(data)
                    
                    # Restore environment variables if needed
                    if 'original_version' in locals() and original_version:
                        os.environ["KEY_ESCROW_KEY_VERSION"] = original_version
            
            except Exception as e:
                print(f"  Error rotating share {share.id}: {str(e)}")
                import traceback
                print(traceback.format_exc())
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