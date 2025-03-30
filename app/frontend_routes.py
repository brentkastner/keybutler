"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Frontend routes for web interface
"""

from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps
import json, base64
from models import User, Vault, KeyShare, Beneficiary, DeadMansSwitch
from app import db


def login_required_frontend(f):
    """Decorator to check if user is logged in for frontend routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('frontend_login'))
        return f(*args, **kwargs)
    return decorated_function


def totp_required_frontend(f):
    """Decorator to check if TOTP is verified for frontend routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'totp_verified' not in session or not session['totp_verified']:
            flash('Please verify your TOTP code first.', 'danger')
            return redirect(url_for('frontend_verify_totp'))
        return f(*args, **kwargs)
    return decorated_function


def register_frontend_routes(app, db):
    """Register all frontend routes with the Flask application."""
    
    @app.route('/')
    def frontend_index():
        """Homepage."""
        return render_template('index.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    def frontend_register():
        """User registration page."""
        from auth import generate_totp_secret
        from werkzeug.security import generate_password_hash
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            # Validation
            if not username or not password:
                flash('Username and password are required.', 'danger')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html')
            
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists.', 'danger')
                return render_template('register.html')
            
            # Generate TOTP secret
            totp_secret = generate_totp_secret()
            
            # Create user
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                totp_secret=totp_secret
            )
            db.session.add(user)
            db.session.commit()
            
            # Create dead man's switch
            switch = DeadMansSwitch(user_id=user.id)
            db.session.add(switch)
            db.session.commit()
            
            # Log event
            from audit import log_event
            log_event(user.id, "user_registered", {"username": username})
            
            # Show TOTP secret to user
            session['temp_totp_secret'] = totp_secret
            return redirect(url_for('frontend_setup_totp'))
        
        return render_template('register.html')
    
    @app.route('/setup-totp')
    def frontend_setup_totp():
        """TOTP setup page after registration."""
        if 'temp_totp_secret' not in session:
            flash('Please register first.', 'danger')
            return redirect(url_for('frontend_register'))
        
        totp_secret = session['temp_totp_secret']
        totp_uri = f"otpauth://totp/KeyEscrow:{session.get('username')}?secret={totp_secret}&issuer=KeyEscrow"
        
        return render_template('setup_totp.html', totp_secret=totp_secret, totp_uri=totp_uri)
    
    @app.route('/login', methods=['GET', 'POST'])
    def frontend_login():
        """Login page."""
        from werkzeug.security import check_password_hash
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Find the user
            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash('Invalid username or password.', 'danger')
                return render_template('login.html')
            
            # Set session
            session['user_id'] = user.id
            session['username'] = user.username
            session['totp_verified'] = False
            
            # Log event
            from audit import log_event
            log_event(user.id, "user_login_password", {"username": username})
            
            return redirect(url_for('frontend_verify_totp'))
        
        return render_template('login.html')
    
    @app.route('/verify-totp', methods=['GET', 'POST'])
    def frontend_verify_totp():
        """TOTP verification page."""
        from auth import verify_totp
        
        if 'user_id' not in session:
            flash('Please log in first.', 'danger')
            return redirect(url_for('frontend_login'))
        
        if request.method == 'POST':
            totp_code = request.form.get('totp_code')
            
            # Get the user
            user = db.session.get(User, session['user_id'])
            if not user:
                session.clear()
                flash('User not found.', 'danger')
                return redirect(url_for('frontend_login'))
            
            # Verify TOTP
            if not verify_totp(user.totp_secret, totp_code):
                flash('Invalid TOTP code.', 'danger')
                return render_template('verify_totp.html')
            
            # Mark TOTP as verified
            session['totp_verified'] = True
            
            # Update last check-in time
            from datetime import datetime
            user.last_check_in = datetime.utcnow()
            db.session.commit()
            
            # Reset dead man's switch if needed
            from dead_mans_switch import reset_dead_mans_switch
            reset_dead_mans_switch(user.id)
            
            # Log event
            from audit import log_event
            log_event(user.id, "user_login_totp_verified", {"username": user.username})
            
            flash('Successfully logged in.', 'success')
            return redirect(url_for('frontend_dashboard'))
        
        return render_template('verify_totp.html')
    
    @app.route('/logout')
    def frontend_logout():
        """Logout route."""
        if 'user_id' in session:
            # Log event
            from audit import log_event
            log_event(session.get('user_id'), "user_logout", {})
        
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('frontend_index'))
    
    @app.route('/dashboard')
    @login_required_frontend
    @totp_required_frontend
    def frontend_dashboard():
        """User dashboard."""
        user = db.session.get(User, session['user_id'])
        vaults = Vault.query.filter_by(user_id=user.id).all()
        
        # Get next check-in date
        from datetime import datetime, timedelta
        next_check_in = user.last_check_in + timedelta(days=user.check_in_interval)
        days_remaining = (next_check_in - datetime.utcnow()).days
        
        # Check dead man's switch status
        switch = DeadMansSwitch.query.filter_by(user_id=user.id).first()
        
        return render_template(
            'dashboard.html',
            user=user,
            vaults=vaults,
            next_check_in=next_check_in,
            days_remaining=days_remaining,
            switch=switch
        )
    
    @app.route('/check-in')
    @login_required_frontend
    @totp_required_frontend
    def frontend_check_in():
        """Perform a check-in."""
        user_id = session.get('user_id')
        
        # Update last check-in time
        from datetime import datetime
        user = db.session.get(User, user_id)
        user.last_check_in = datetime.utcnow()
        db.session.commit()
        
        # Reset dead man's switch
        from dead_mans_switch import reset_dead_mans_switch
        reset_dead_mans_switch(user_id)
        
        # Log event
        from audit import log_event
        log_event(user_id, "user_check_in", {})
        
        flash('Check-in successful.', 'success')
        return redirect(url_for('frontend_dashboard'))
    
    @app.route('/vault/create', methods=['GET', 'POST'])
    @login_required_frontend
    @totp_required_frontend
    def frontend_create_vault():
        """Create a new vault."""
        from crypto import ShamirSecretSharing, derive_key, encrypt_data
        import json
        import base64
        
        if request.method == 'POST':
            vault_id = request.form.get('vault_id')
            diceware_keyphrase = request.form.get('diceware_keyphrase')
            num_shares = int(request.form.get('num_shares', 3))
            threshold = int(request.form.get('threshold', 2))
            
            # Validation
            if not vault_id or not diceware_keyphrase:
                flash('Vault ID and diceware keyphrase are required.', 'danger')
                return render_template('create_vault.html')
            
            if threshold > num_shares:
                flash('Threshold cannot be greater than the number of shares.', 'danger')
                return render_template('create_vault.html')
            
            user_id = session.get('user_id')
            
            # Check if vault already exists
            existing_vault = Vault.query.filter_by(vault_id=vault_id).first()
            if existing_vault:
                flash('A vault with this ID already exists.', 'danger')
                return render_template('create_vault.html')
            
            # Create vault
            vault = Vault(vault_id=vault_id, user_id=user_id)
            db.session.add(vault)
            db.session.flush()
            
            # Create shares
            shares = ShamirSecretSharing.create_shares(diceware_keyphrase, num_shares, threshold)
            
            # Store encrypted shares
            for i, share_value in shares:
                # Derive encryption key
                share_key, salt = derive_key(f"share_{i}_{vault_id}")
                
                # Encrypt share
                encrypted_share = json.dumps({
                    "salt": base64.b64encode(salt).decode('utf-8'),
                    "share": encrypt_data(share_value, share_key)
                })
                
                # Store share
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
            
            flash('Vault created successfully.', 'success')
            return redirect(url_for('frontend_dashboard'))
        
        return render_template('create_vault.html')
    
    @app.route('/vault/<vault_id>')
    @login_required_frontend
    @totp_required_frontend
    def frontend_view_vault(vault_id):
        """View vault details."""
        user_id = session.get('user_id')
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id, user_id=user_id).first()
        if not vault:
            flash('Vault not found or you don\'t have access.', 'danger')
            return redirect(url_for('frontend_dashboard'))
        
        # Get shares and beneficiaries
        shares = KeyShare.query.filter_by(vault_id=vault.id).all()
        beneficiaries = Beneficiary.query.filter_by(vault_id=vault.id).all()
        
        return render_template('view_vault.html', vault=vault, shares=shares, beneficiaries=beneficiaries)
    
    @app.route('/vault/<vault_id>/add-beneficiary', methods=['GET', 'POST'])
    @login_required_frontend
    @totp_required_frontend
    def frontend_add_beneficiary(vault_id):
        """Add a beneficiary to a vault."""
        user_id = session.get('user_id')
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id, user_id=user_id).first()
        if not vault:
            flash('Vault not found or you don\'t have access.', 'danger')
            return redirect(url_for('frontend_dashboard'))
        
        if request.method == 'POST':
            beneficiary_username = request.form.get('username')
            beneficiary_email = request.form.get('email')
            beneficiary_public_key = request.form.get('public_key')
            threshold_index = int(request.form.get('threshold_index', 1))
            
            # Validation
            if not all([beneficiary_username, beneficiary_email, beneficiary_public_key]):
                flash('All fields are required.', 'danger')
                return render_template('add_beneficiary.html', vault=vault)
            
            # Check if beneficiary already exists
            existing_beneficiary = Beneficiary.query.filter_by(
                vault_id=vault.id, username=beneficiary_username).first()
            if existing_beneficiary:
                flash('Beneficiary already exists for this vault.', 'danger')
                return render_template('add_beneficiary.html', vault=vault)
            
            # Create beneficiary
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
            
            flash('Beneficiary added successfully.', 'success')
            return redirect(url_for('frontend_view_vault', vault_id=vault_id))
        
        return render_template('add_beneficiary.html', vault=vault)
    
    @app.route('/switch-settings', methods=['GET', 'POST'])
    @login_required_frontend
    @totp_required_frontend
    def frontend_switch_settings():
        """Configure dead man's switch settings."""
        user_id = session.get('user_id')
        user = db.session.get(User, user_id)
        
        if request.method == 'POST':
            check_in_interval = int(request.form.get('check_in_interval', 7))
            
            # Validation
            if check_in_interval <= 0:
                flash('Check-in interval must be positive.', 'danger')
                return render_template('switch_settings.html', user=user)
            
            # Update settings
            user.check_in_interval = check_in_interval
            db.session.commit()
            
            # Log event
            from audit import log_event
            log_event(user_id, "dead_mans_switch_configured", {
                "check_in_interval": check_in_interval
            })
            
            flash('Dead man\'s switch settings updated.', 'success')
            return redirect(url_for('frontend_dashboard'))
        
        return render_template('switch_settings.html', user=user)

    # Beneficiary access routes
    @app.route('/beneficiary-access')
    def frontend_beneficiary_access():
        """Landing page for beneficiaries to request access."""
        return render_template('beneficiary_access.html')
    
    @app.route('/beneficiary-access/<vault_id>', methods=['GET', 'POST'])
    def frontend_request_access(vault_id):
        """Request access to a vault as a beneficiary."""
        import secrets
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id).first()
        if not vault:
            flash('Vault not found.', 'danger')
            return redirect(url_for('frontend_beneficiary_access'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            
            # Find the beneficiary
            beneficiary = Beneficiary.query.filter_by(vault_id=vault.id, username=username).first()
            if not beneficiary:
                flash('You are not a beneficiary of this vault.', 'danger')
                return render_template('request_access.html', vault_id=vault_id)
            
            # Check if the dead man's switch has been triggered
            switch = DeadMansSwitch.query.filter_by(user_id=vault.user_id).first()
            if not switch or switch.status != 'triggered':
                flash('Access to this vault is not available at this time.', 'danger')
                return render_template('request_access.html', vault_id=vault_id)
            
            # Generate request ID
            request_id = secrets.token_hex(16)
            
            # Log event
            from audit import log_event
            log_event(None, "access_requested", {
                "vault_id": vault_id,
                "beneficiary_username": username
            })
            
            # Reconstruct the secret
            try:
                # Get all shares for this vault
                shares = KeyShare.query.filter_by(vault_id=vault.id).all()
                
                # Decrypt each share
                decrypted_shares = []
                for share in shares:
                    # Parse the encrypted share data
                    share_data = json.loads(share.encrypted_share)
                    salt = base64.b64decode(share_data['salt'])
                    encrypted_share = share_data['share']
                    
                    # Derive the key for this share
                    from crypto import derive_key, decrypt_data
                    share_key, _ = derive_key(f"share_{share.share_index}_{vault_id}", salt)
                    
                    # Decrypt the share
                    decrypted_share = decrypt_data(encrypted_share, share_key)
                    decrypted_shares.append((share.share_index, decrypted_share))
                
                # Reconstruct the secret using Shamir's Secret Sharing
                from crypto import ShamirSecretSharing
                # Use a threshold (typically half of the shares + 1)
                threshold = (len(shares) // 2) + 1
                diceware_keyphrase = ShamirSecretSharing.reconstruct_secret(decrypted_shares, threshold)
                
                # In a real implementation, you would encrypt this with the beneficiary's public key
                # For the prototype, we'll just pass it directly
                
                return render_template(
                    'access_granted.html',
                    vault_id=vault_id,
                    username=username,
                    request_id=request_id,
                    keyphrase=diceware_keyphrase
                )
            except Exception as e:
                # Log the error
                import traceback
                print(f"Error reconstructing secret: {str(e)}")
                print(traceback.format_exc())
                flash('An error occurred while retrieving the key.', 'danger')
                return render_template('request_access.html', vault_id=vault_id)
            
        return render_template('request_access.html', vault_id=vault_id)