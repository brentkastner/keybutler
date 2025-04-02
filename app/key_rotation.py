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

# Import the Flask app first
from app import app, db
from models import KeyShare, Vault
from crypto import create_share_key, encrypt_data, decrypt_data, SecureKey
from secure_config import get_key_version, secure_wipe

def rotate_keys(new_master_key, new_pepper):
    """
    Rotate encryption keys by re-encrypting all shares with new keys.
    
    Args:
        new_master_key: New Key
        new_pepper: New Pepper

        Update the ENV variables after a successful rotation
    """
    print("Starting key rotation process...")
    
    # Create an application context
    with app.app_context():
        # Get all vaults
        vaults = Vault.query.all()
        print(f"Found {len(vaults)} vaults to process")
        
        # Current key version
        new_version = get_key_version() + 1
        current_version = get_key_version()

        print(f"Current Key Version from .env key rotation.py {current_version}")
        
        print(f"Rotating from version {current_version} to {new_version}")
        
        # Process each vault
        for vault in vaults:
            print(f"Processing vault {vault.vault_id}")
            vault_success = True
            
            # Get all system shares for this vault
            system_shares = KeyShare.query.filter_by(vault_id=vault.id, share_type="system").all()
            
            # Process each share
            for share in system_shares:
                try:
                    print(f"  Rotating share {share.id} (index: {share.share_index})")
                    
                    # Decode the share data
                    share_data = json.loads(share.encrypted_share)
                    salt = base64.b64decode(share_data['salt'])
                    
                    # Get the version from the share data if available
                    share_version = share_data.get('version', current_version)
                    
                    # Temporary store for sensitive data to ensure wiping
                    sensitive_data = []
                    
                    try:
                        # Set up the environment for decryption using the appropriate key
                        current_master_key = os.environ.get("KEY_ESCROW_MASTER_KEY")
                        current_pepper = os.environ.get("KEY_ESCROW_KEY_PEPPER")
                        
                        # For backwards compatibility with unversioned shares
                        if 'version' not in share_data:
                            print(f"  Share has no version information, using original key derivation")
                            # Use the original key derivation without versioning
                            share_key, _ = create_share_key(
                                share.share_index, 
                                vault.vault_id, 
                                "system_share", 
                                salt
                            )
                        else:
                            print(f"  Share has version {share_version}, using versioned key derivation")
                            # Use versioned key derivation
                            
                            # Derive key with correct version
                            share_key, _ = create_share_key(
                                share.share_index, 
                                vault.vault_id, 
                                "system_share", 
                                salt
                            )
                        
                        sensitive_data.append(share_key)
                        print(f"  Derived decryption key (length: {len(share_key)})")
                        
                        # Decrypt the data with the appropriate key
                        print(f"  Attempting to decrypt share data")
                        try:
                            decrypted_share = decrypt_data(share_data['share'], share_key)
                            sensitive_data.append(decrypted_share)
                            print(f"  Successfully decrypted share data (length: {len(decrypted_share)})")
                        except Exception as decrypt_error:
                            print(f"  CRITICAL ERROR: Failed to decrypt share data: {str(decrypt_error)}")
                            vault_success = False
                            # Abort processing this share
                            raise ValueError(f"Unable to decrypt share {share.id} for vault {vault.vault_id}. Key rotation cannot proceed.")
                        
                        # Restore the original environment variables
                        if new_master_key is not None:
                            os.environ["KEY_ESCROW_MASTER_KEY"] = new_master_key
                        elif current_master_key:
                            os.environ.pop("KEY_ESCROW_MASTER_KEY")
                        
                        if new_pepper is not None:
                            os.environ["KEY_ESCROW_KEY_PEPPER"] = new_pepper
                        elif current_pepper:
                            os.environ.pop("KEY_ESCROW_KEY_PEPPER")
                        
                        # Generate new salt and key for re-encryption with current settings
                        new_salt = os.urandom(16)
                        print(f"  Generated new salt for encryption")
                        
                        # Ensure current version is used for encryption
                        os.environ["KEY_ESCROW_KEY_VERSION"] = str(new_version)

                        # Derive a new key for encryption
                        print(f"  Deriving new encryption key with current environment settings")
                        new_key, _ = create_share_key(
                            share.share_index, 
                            vault.vault_id, 
                            "system_share", 
                            new_salt
                        )
                        sensitive_data.append(new_key)
                        print(f"  Derived new encryption key (length: {len(new_key)})")
                        
                        # Re-encrypt with new key
                        print(f"  Re-encrypting share data with new key")
                        encrypted_share = encrypt_data(decrypted_share, new_key)
                        
                        # Update the database
                        share.encrypted_share = json.dumps({
                            "salt": base64.b64encode(new_salt).decode('utf-8'),
                            "share": encrypted_share,
                            "version": current_version
                        })
                        print(f"  Updated share data with new encryption")
                        
                    finally:
                        # Clear all sensitive data
                        print(f"  Wiping {len(sensitive_data)} sensitive data items")
                        for data in sensitive_data:
                            if data:
                                secure_wipe(data)
                        
                        # Restore any remaining environment variables
                        for var_name, original_value in [
                            ("KEY_ESCROW_MASTER_KEY", current_master_key),
                            ("KEY_ESCROW_KEY_PEPPER", current_pepper),
                            ("KEY_ESCROW_KEY_VERSION", str(current_version))
                        ]:
                            if original_value is not None and var_name in os.environ:
                                os.environ[var_name] = original_value
                
                except Exception as e:
                    print(f"  Error rotating share {share.id}: {str(e)}")
                    import traceback
                    print(traceback.format_exc())
                    vault_success = False
                    break  # Stop processing other shares for this vault
            
            # Only commit changes if ALL shares were successfully processed
            if vault_success:
                db.session.commit()
                print(f"Completed rotation for vault {vault.vault_id}")
            else:
                print(f"ABORTING rotation for vault {vault.vault_id} due to errors")
                db.session.rollback()
                print(f"Changes have been rolled back for vault {vault.vault_id}")
                # Exit the entire process to prevent partial rotation
                print("CRITICAL: Key rotation process aborted. Some vaults could not be rotated.")
                sys.exit(1)
        
        print("Key rotation complete! Update environment variables with the new key, pepper, and version")

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
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "generate":
            generate_new_keys()
        elif sys.argv[1] == "rotate-master-key":
            if len(sys.argv) < 3:
                print("Error: Old master key required")
                print("Usage: python key_rotation.py rotate-master-key OLD_MASTER_KEY")
                sys.exit(1)
            old_master_key = sys.argv[2]
            rotate_keys(old_master_key=old_master_key)
        elif sys.argv[1] == "rotate-pepper":
            if len(sys.argv) < 3:
                print("Error: Old pepper required")
                print("Usage: python key_rotation.py rotate-pepper OLD_PEPPER")
                sys.exit(1)
            old_pepper = sys.argv[2]
            rotate_keys(old_pepper=old_pepper)
        elif sys.argv[1] == "rotate-both":
            if len(sys.argv) < 4:
                print("Error: Both new master key and new pepper required")
                print("Usage: python key_rotation.py rotate-both NEW_MASTER_KEY NEW_PEPPER")
                sys.exit(1)
            new_master_key = sys.argv[2]
            new_pepper = sys.argv[3]
            rotate_keys(new_master_key=new_master_key, new_pepper=new_pepper)
        elif sys.argv[1] == "help":
            print("Key Rotation Utility")
            print("===================")
            print("Commands:")
            print("  generate                  - Generate new master key and pepper")
            print("  rotate-master-key KEY     - Rotate using previous master key")
            print("  rotate-pepper PEPPER      - Rotate using previous pepper")
            print("  rotate-both KEY PEPPER    - Rotate using both previous values")
            print("  help                      - Show this help message")
        else:
            print(f"Unknown command: {sys.argv[1]}")
            print("Available commands: generate, rotate-master-key, rotate-pepper, rotate-both, help")
            print("Use 'python key_rotation.py help' for more information")
    else:
        # Just rotating version number, no key material changes
        rotate_keys()