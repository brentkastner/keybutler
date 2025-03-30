"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
API routes for the application
"""

import base64
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from auth import verify_totp
from crypto import ShamirSecretSharing, derive_key, encrypt_data
from models import Beneficiary, DeadMansSwitch, KeyShare, User, Vault


def register_routes(app: Flask) -> None:
    """Register all routes with the Flask application."""
    
    # --------------------------------------------------------
    # Authentication Middleware
    # --------------------------------------------------------

    def login_required(f):
        """Decorator to check if user is logged in for API routes."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            print(f"API login_required decorator - Session: {dict(session)}")
            if 'user_id' not in session:
                print("API login_required: No user_id in session")
                return jsonify({"error": "Authentication required"}), 401
            return f(*args, **kwargs)
        return decorated_function


    def require_totp(f):
        """Decorator to check if TOTP is verified for API routes."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            print(f"API require_totp decorator - Session: {dict(session)}")
            if 'totp_verified' not in session or not session['totp_verified']:
                print("API require_totp: TOTP not verified in session")
                return jsonify({"error": "TOTP verification required"}), 401
            return f(*args, **kwargs)
        return decorated_function
    
    
    # --------------------------------------------------------
    # Authentication Routes
    # --------------------------------------------------------

    @app.route('/api/register', methods=['POST'])
    def register():
        """Register a new user."""
        data = request.get_json()
        
        if not data:
            print("API Register: No JSON data received")
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"error": "Username already exists"}), 400
        
        # Generate TOTP secret
        from auth import generate_totp_secret
        totp_secret = generate_totp_secret()
        
        # Create user
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            totp_secret=totp_secret,
            last_check_in=datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
        
        # Create a dead man's switch for the user
        switch = DeadMansSwitch(user_id=user.id)
        db.session.add(switch)
        db.session.commit()
        
        # Log event
        from audit import log_event
        log_event(user.id, "user_registered", {"username": username})
        
        return jsonify({
            "message": "User registered successfully",
            "totp_secret": totp_secret
        }), 201


    @app.route('/api/login', methods=['POST'])
    def login():
        """Login a user with username and password."""
        data = request.get_json()
        
        if not data:
            print("API Login: No JSON data received")
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        print(f"API Login attempt: username={username}")
        
        if not username or not password:
            print("API Login: Username and password are required")
            return jsonify({"error": "Username and password are required"}), 400
        
        # Find the user
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f"API Login: User {username} not found")
            return jsonify({"error": "Invalid username or password"}), 401
            
        print(f"API Login: User found with ID {user.id}")
        
        if not check_password_hash(user.password_hash, password):
            print("API Login: Invalid password")
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Set session
        session['user_id'] = user.id
        session['username'] = username
        session['totp_verified'] = False
        
        print(f"API Login: Session set for user_id={user.id}")
        
        # Log event
        from audit import log_event
        log_event(user.id, "user_login_password", {"username": username})
        
        return jsonify({
            "message": "Password verified. TOTP verification required."
        }), 200


    @app.route('/api/verify-totp', methods=['POST'])
    def verify_totp_code():
        """Verify a TOTP code after password authentication."""
        if 'user_id' not in session:
            print("API TOTP Verify: No user_id in session")
            return jsonify({"error": "You must login first"}), 401
        
        data = request.get_json()
        if not data:
            print("API TOTP Verify: No JSON data received")
            return jsonify({"error": "No JSON data received"}), 400
            
        totp_code = data.get('totp_code')
        
        print(f"API TOTP Verify: Verifying code for user_id={session['user_id']}")
        
        if not totp_code:
            print("API TOTP Verify: TOTP code is required")
            return jsonify({"error": "TOTP code is required"}), 400
        
        # Get the user
        user = db.session.get(User, session['user_id'])
        if not user:
            print(f"API TOTP Verify: User {session['user_id']} not found")
            return jsonify({"error": "User not found"}), 404
        
        # Verify TOTP
        if not verify_totp(user.totp_secret, totp_code):
            print("API TOTP Verify: Invalid TOTP code")
            return jsonify({"error": "Invalid TOTP code"}), 401
        
        # Mark TOTP as verified
        session['totp_verified'] = True
        
        print("API TOTP Verify: TOTP verified successfully")
        
        # Update last check-in time
        from datetime import datetime
        user.last_check_in = datetime.utcnow()
        db.session.commit()
        
        # Reset the dead man's switch if it's in an alert stage
        from dead_mans_switch import reset_dead_mans_switch
        reset_dead_mans_switch(user.id)
        
        # Log event
        from audit import log_event
        log_event(user.id, "user_login_totp_verified", {"username": user.username})
        
        return jsonify({
            "message": "TOTP verified successfully. You are now fully authenticated."
        }), 200


    @app.route('/api/logout', methods=['POST'])
    @login_required
    def logout():
        """Logout a user."""
        user_id = session.get('user_id')
        session.clear()
        
        # Log event
        from audit import log_event
        log_event(user_id, "user_logout", {})
        
        return jsonify({
            "message": "Logged out successfully"
        }), 200


    @app.route('/api/check-in', methods=['POST'])
    @login_required
    @require_totp
    def check_in():
        """Perform a check-in to reset the dead man's switch."""
        user_id = session.get('user_id')
        print(f"API Check-in: Processing for user_id={user_id}")
        
        # Get the user
        user = db.session.get(User, user_id)
        if not user:
            print(f"API Check-in: User {user_id} not found")
            return jsonify({"error": "User not found"}), 404
            
        print(f"API Check-in: Found user {user.username}")
        
        # Update last check-in time
        from datetime import datetime
        user.last_check_in = datetime.utcnow()
        db.session.commit()
        
        # Reset the dead man's switch
        from dead_mans_switch import reset_dead_mans_switch
        reset_dead_mans_switch(user_id)
        
        # Log event
        from audit import log_event
        log_event(user_id, "user_check_in", {})
        
        print(f"API Check-in: Successful for user {user.username}")
        
        return jsonify({
            "message": "Check-in successful",
            "next_check_in_required": (datetime.utcnow() + timedelta(days=user.check_in_interval)).isoformat()
        }), 200
    
    
    # --------------------------------------------------------
    # Vault Management Routes
    # --------------------------------------------------------

    @app.route('/api/vault', methods=['POST'])
    @login_required
    @require_totp
    def create_vault():
        """Create a new vault with a diceware keyphrase."""
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        vault_id = data.get('vault_id')
        diceware_keyphrase = data.get('diceware_keyphrase')
        num_shares = data.get('num_shares', 3)
        threshold = data.get('threshold', 2)
        
        if not vault_id or not diceware_keyphrase:
            return jsonify({"error": "Vault ID and diceware keyphrase are required"}), 400
        
        if threshold > num_shares:
            return jsonify({"error": "Threshold cannot be greater than the number of shares"}), 400
        
        user_id = session.get('user_id')
        
        # Check if a vault with this ID already exists
        existing_vault = Vault.query.filter_by(vault_id=vault_id).first()
        if existing_vault:
            return jsonify({"error": "A vault with this ID already exists"}), 400
        
        # Create the vault
        vault = Vault(vault_id=vault_id, user_id=user_id)
        db.session.add(vault)
        db.session.flush()  # Get the vault ID without committing
        
        # Create the shares using Shamir's Secret Sharing
        shares = ShamirSecretSharing.create_shares(diceware_keyphrase, num_shares, threshold)
        
        # Encrypt and store each share
        for i, share_value in shares:
            # Derive a key for encrypting this share
            share_key, salt = derive_key(f"share_{i}_{vault_id}")
            
            # Encrypt the share
            encrypted_share = json.dumps({
                "salt": base64.b64encode(salt).decode('utf-8'),
                "share": encrypt_data(share_value, share_key)
            })
            
            # Store the share
            key_share = KeyShare(
                vault_id=vault.id,
                encrypted_share=encrypted_share,
                share_index=i
            )
            db.session.add(key_share)
        
        db.session.commit()
        
        # Log event
        from audit import log_event
        log_event(user_id, "vault_created", {
            "vault_id": vault_id,
            "num_shares": num_shares,
            "threshold": threshold
        })
        
        return jsonify({
            "message": "Vault created successfully",
            "vault_id": vault_id,
            "num_shares": num_shares,
            "threshold": threshold
        }), 201


    @app.route('/api/vaults', methods=['GET'])
    @login_required
    @require_totp
    def list_vaults():
        """List all vaults owned by the user."""
        user_id = session.get('user_id')
        
        vaults = Vault.query.filter_by(user_id=user_id).all()
        
        result = []
        for vault in vaults:
            # Count shares and beneficiaries
            share_count = KeyShare.query.filter_by(vault_id=vault.id).count()
            beneficiary_count = Beneficiary.query.filter_by(vault_id=vault.id).count()
            
            result.append({
                "vault_id": vault.vault_id,
                "created_at": vault.created_at.isoformat(),
                "share_count": share_count,
                "beneficiary_count": beneficiary_count
            })
        
        return jsonify({
            "vaults": result
        }), 200


    @app.route('/api/vault/<vault_id>', methods=['GET'])
    @login_required
    @require_totp
    def get_vault_details(vault_id):
        """Get details for a specific vault."""
        user_id = session.get('user_id')
        
        vault = Vault.query.filter_by(vault_id=vault_id, user_id=user_id).first()
        if not vault:
            return jsonify({"error": "Vault not found or you don't have access"}), 404
        
        # Get shares and beneficiaries
        shares = KeyShare.query.filter_by(vault_id=vault.id).all()
        beneficiaries = Beneficiary.query.filter_by(vault_id=vault.id).all()
        
        share_info = []
        for share in shares:
            share_info.append({
                "share_index": share.share_index,
                "id": share.id
            })
        
        beneficiary_info = []
        for beneficiary in beneficiaries:
            beneficiary_info.append({
                "username": beneficiary.username,
                "email": beneficiary.notification_email,
                "threshold_index": beneficiary.threshold_index
            })
        
        return jsonify({
            "vault_id": vault.vault_id,
            "created_at": vault.created_at.isoformat(),
            "shares": share_info,
            "beneficiaries": beneficiary_info
        }), 200
    
    
    # --------------------------------------------------------
    # Beneficiary Management Routes
    # --------------------------------------------------------

    @app.route('/api/beneficiary', methods=['POST'])
    @login_required
    @require_totp
    def add_beneficiary():
        """Add a beneficiary to a vault."""
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        vault_id = data.get('vault_id')
        beneficiary_username = data.get('username')
        beneficiary_email = data.get('email')
        beneficiary_public_key = data.get('public_key')
        threshold_index = data.get('threshold_index', 1)
        
        if not all([vault_id, beneficiary_username, beneficiary_email, beneficiary_public_key]):
            return jsonify({"error": "Missing required fields"}), 400
        
        user_id = session.get('user_id')
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id, user_id=user_id).first()
        if not vault:
            return jsonify({"error": "Vault not found or you don't have access"}), 404
        
        # Check if beneficiary already exists for this vault
        existing_beneficiary = Beneficiary.query.filter_by(
            vault_id=vault.id, username=beneficiary_username).first()
        if existing_beneficiary:
            return jsonify({"error": "Beneficiary already exists for this vault"}), 400
        
        # Create the beneficiary
        beneficiary = Beneficiary(
            vault_id=vault.id,
            username=beneficiary_username,
            notification_email=beneficiary_email,
            public_key=beneficiary_public_key,
            threshold_index=threshold_index
        )
        db.session.add(beneficiary)
        db.session.commit()
        
        # Log event
        from audit import log_event
        log_event(user_id, "beneficiary_added", {
            "vault_id": vault_id,
            "beneficiary_username": beneficiary_username,
            "threshold_index": threshold_index
        })
        
        return jsonify({
            "message": "Beneficiary added successfully",
            "vault_id": vault_id,
            "beneficiary_username": beneficiary_username
        }), 201


    @app.route('/api/beneficiary/<int:beneficiary_id>', methods=['DELETE'])
    @login_required
    @require_totp
    def remove_beneficiary(beneficiary_id):
        """Remove a beneficiary from a vault."""
        user_id = session.get('user_id')
        
        # Find the beneficiary
        beneficiary = db.session.get(Beneficiary, beneficiary_id)
        if not beneficiary:
            return jsonify({"error": "Beneficiary not found"}), 404
        
        # Check if the user has access to the vault
        vault = db.session.get(Vault, beneficiary.vault_id)
        if not vault or vault.user_id != user_id:
            return jsonify({"error": "Vault not found or you don't have access"}), 403
        
        # Delete the beneficiary
        db.session.delete(beneficiary)
        db.session.commit()
        
        # Log event
        from audit import log_event
        log_event(user_id, "beneficiary_removed", {
            "vault_id": vault.vault_id,
            "beneficiary_username": beneficiary.username
        })
        
        return jsonify({
            "message": "Beneficiary removed successfully"
        }), 200
    
    
    # --------------------------------------------------------
    # Dead Man's Switch Management Routes
    # --------------------------------------------------------

    @app.route('/api/setup-dead-mans-switch', methods=['POST'])
    @login_required
    @require_totp
    def setup_dead_mans_switch():
        """Configure the dead man's switch settings."""
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        check_in_interval = data.get('check_in_interval')
        
        if not check_in_interval or not isinstance(check_in_interval, int) or check_in_interval <= 0:
            return jsonify({"error": "Valid check-in interval is required"}), 400
        
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        
        # Update the check-in interval
        user.check_in_interval = check_in_interval
        db.session.commit()
        
        # Log event
        from audit import log_event
        log_event(user_id, "dead_mans_switch_configured", {
            "check_in_interval": check_in_interval
        })
        
        return jsonify({
            "message": "Dead man's switch configured successfully",
            "check_in_interval": check_in_interval,
            "next_check_in_required": (datetime.utcnow() + timedelta(days=check_in_interval)).isoformat()
        }), 200
    
    
    # --------------------------------------------------------
    # Beneficiary Access Routes
    # --------------------------------------------------------

    @app.route('/api/request-access/<vault_id>', methods=['POST'])
    def request_vault_access(vault_id):
        """Request access to a vault as a beneficiary."""
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        username = data.get('username')
        
        if not username:
            return jsonify({"error": "Username is required"}), 400
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id).first()
        if not vault:
            return jsonify({"error": "Vault not found"}), 404
        
        # Find the beneficiary
        beneficiary = Beneficiary.query.filter_by(vault_id=vault.id, username=username).first()
        if not beneficiary:
            return jsonify({"error": "You are not a beneficiary of this vault"}), 403
        
        # Check if the dead man's switch has been triggered
        switch = DeadMansSwitch.query.filter_by(user_id=vault.user_id).first()
        if not switch or switch.status != 'triggered':
            return jsonify({"error": "Access to this vault is not available at this time"}), 403
        
        # Generate request ID for the next step
        request_id = secrets.token_hex(16)
        
        # Log event
        from audit import log_event
        log_event(None, "access_requested", {
            "vault_id": vault_id,
            "beneficiary_username": username
        })
        
        return jsonify({
            "message": "Access request received. Further authentication required.",
            "request_id": request_id
        }), 200


    @app.route('/api/retrieve-key/<vault_id>', methods=['POST'])
    def retrieve_key(vault_id):
        """Retrieve the diceware keyphrase for a beneficiary."""
        # This is a simplified version for the prototype
        # In a real implementation, this would require strong authentication
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        request_id = data.get('request_id')
        username = data.get('username')
        authentication_proof = data.get('authentication_proof')
        
        if not all([request_id, username, authentication_proof]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id).first()
        if not vault:
            return jsonify({"error": "Vault not found"}), 404
        
        # Find the beneficiary
        beneficiary = Beneficiary.query.filter_by(vault_id=vault.id, username=username).first()
        if not beneficiary:
            return jsonify({"error": "You are not a beneficiary of this vault"}), 403
        
        # Check if the dead man's switch has been triggered
        switch = DeadMansSwitch.query.filter_by(user_id=vault.user_id).first()
        if not switch or switch.status != 'triggered':
            return jsonify({"error": "Access to this vault is not available at this time"}), 403
        
        # In a real implementation:
        # 1. Verify the authentication proof
        # 2. Retrieve the key shares
        # 3. Decrypt the shares
        # 4. Reconstruct the secret using Shamir's Secret Sharing
        # 5. Encrypt the secret with the beneficiary's public key
        
        # For the prototype, we'll just return a placeholder
        
        # Log event
        from audit import log_event
        log_event(None, "key_retrieved", {
            "vault_id": vault_id,
            "beneficiary_username": username
        })
        
        return jsonify({
            "message": "Key retrieval successful",
            "encrypted_keyphrase": "This would be the encrypted keyphrase in a real implementation"
        }), 200
    
    
    # --------------------------------------------------------
    # System Health Routes
    # --------------------------------------------------------
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Simple health check endpoint."""
        return jsonify({
            "status": "ok",
            "time": datetime.utcnow().isoformat()
        }), 200


    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return jsonify({"error": "Endpoint not found"}), 404


    @app.errorhandler(500)
    def server_error(error):
        """Handle 500 errors."""
        return jsonify({"error": "Internal server error"}), 500