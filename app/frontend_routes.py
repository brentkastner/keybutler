"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Frontend routes for web interface
"""

from flask import Flask, render_template, redirect, url_for, request, session, flash
from functools import wraps
import json, base64
from models import User, Vault, KeyShare, Beneficiary, DeadMansSwitch
from crypto import ShamirSecretSharing, decrypt_data, create_share_key
from app import db

#TODO: check each function and secure wipe everything sensitive

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
        """Create a new vault with real security."""
        import requests
        import json
        
        if request.method == 'POST':
            vault_name = request.form.get('vault_name')
            secret = request.form.get('secret')
            
            # Validation
            if not vault_name or not secret:
                flash('Vault Name and secret are required.', 'danger')
                return render_template('create_vault.html')
            
            # Create the vault through the API
            api_url = url_for('create_vault', _external=True)
            headers = {'Content-Type': 'application/json'}
            
            # Include session cookie to maintain authentication
            cookies = {key: value for key, value in request.cookies.items()}
            
            #TODO: Change vaultname and vaultid
            payload = {
                'vault_name': vault_name,
                'secret': secret
            }
            
            response = requests.post(
                api_url, 
                headers=headers,
                cookies=cookies,
                json=payload,
                verify=False  # For development only - remove in production!
            )
            
            if response.status_code == 201:
                # Success
                data = response.json()
                
                # Now we have the vault data including the owner's share
                return render_template(
                    'show_owner_share.html',
                    vault_id=data['vault_id'],
                    vault_name=data['vault_name'],
                    owner_share=data['owner_share'],
                    total_shares=data['num_shares'],
                    threshold=data['threshold']
                )
            else:
                # Error handling
                try:
                    error_data = response.json()
                    flash(f"Error: {error_data.get('error', 'Unknown error')}", 'danger')
                except:
                    flash(f"Error: Could not create vault. Status code: {response.status_code}", 'danger')
                
                return render_template('create_vault.html')
        
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
        """Add a beneficiary to a vault with secure share management."""
        import requests
        import json
        
        user_id = session.get('user_id')
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id, user_id=user_id).first()
        if not vault:
            flash('Vault not found or you don\'t have access.', 'danger')
            return redirect(url_for('frontend_dashboard'))
        
        # Get existing beneficiaries for display in the form
        beneficiaries = Beneficiary.query.filter_by(vault_id=vault.id).all()
        
        if request.method == 'POST':
            # Get basic beneficiary information
            beneficiary_username = request.form.get('username')
            beneficiary_email = request.form.get('email')
            #beneficiary_public_key = request.form.get('public_key')
            threshold_index = int(request.form.get('threshold_index', 1))
            owner_share = request.form.get('owner_share')
            
            # Validation for basic fields
            if not all([beneficiary_username, beneficiary_email, owner_share]):
                flash('All fields are required, including your owner share.', 'danger')
                return render_template('add_beneficiary.html', vault=vault, beneficiaries=beneficiaries)
            
            # Collect shares from existing beneficiaries
            beneficiary_shares = {}
            for beneficiary in beneficiaries:
                share_key = f"beneficiary_share_{beneficiary.id}"
                beneficiary_share = request.form.get(share_key)
                
                if not beneficiary_share:
                    flash(f'Share for beneficiary {beneficiary.username} is required.', 'danger')
                    return render_template('add_beneficiary.html', vault=vault, beneficiaries=beneficiaries)
                
                # Get the share index if available
                share_index = None
                if beneficiary.key_share:
                    share_index = beneficiary.key_share.share_index
                
                beneficiary_shares[beneficiary.id] = {
                    'username': beneficiary.username,
                    'share_index': share_index,
                    'share_value': beneficiary_share
                }
            
            # Add the beneficiary through the API
            api_url = url_for('add_beneficiary', _external=True)
            headers = {'Content-Type': 'application/json'}
            
            # Include session cookie to maintain authentication
            cookies = {key: value for key, value in request.cookies.items()}
            
            # Prepare payload with owner share and beneficiary shares
            payload = {
                'vault_id': vault_id,
                'username': beneficiary_username,
                'email': beneficiary_email,
                'threshold_index': threshold_index,
                'owner_share': owner_share,
                'beneficiary_shares': beneficiary_shares
            }
            
            try:
                # Debug logging before sending request
                print(f"Sending request to {api_url}")
                print(f"Payload: {json.dumps(payload, indent=2)}")
                
                response = requests.post(
                    api_url, 
                    headers=headers,
                    cookies=cookies,
                    json=payload,
                    verify=False  # For development only - remove in production!
                )
                
                # Debug logging after receiving response
                print(f"Response status: {response.status_code}")
                print(f"Response headers: {response.headers}")
                
                if response.status_code == 201:
                    # Success
                    data = response.json()
                    
                    # Format the existing beneficiary shares for display
                    existing_beneficiaries_data = []
                    for beneficiary_data in data.get('existing_beneficiary_shares', []):
                        existing_beneficiaries_data.append({
                            'username': beneficiary_data['username'],
                            'share': beneficiary_data['share']
                        })
                    
                    # Log successful beneficiary addition
                    print(f"Successfully added beneficiary {beneficiary_username} to vault {vault_id}")
                    print(f"Total shares: {data['total_shares']}, Threshold: {data['threshold']}")
                    
                    # Now we have the data including all shares
                    return render_template(
                        'show_all_shares.html',
                        vault_id=data['vault_id'],
                        beneficiary_username=data['beneficiary_username'],
                        beneficiary_share=data['beneficiary_share'],
                        owner_share=data['owner_share'],
                        existing_beneficiaries=existing_beneficiaries_data,
                        total_shares=data['total_shares'],
                        threshold=data['threshold']
                    )
                else:
                    # Error handling
                    try:
                        error_data = response.json()
                        error_message = error_data.get('error', 'Unknown error')
                        
                        # Log detailed error for debugging
                        print(f"API Error: {error_message}")
                        print(f"Response status: {response.status_code}")
                        print(f"Response content: {response.content.decode()[:500]}")
                        
                        flash(f"Error: {error_message}", 'danger')
                    except Exception as parse_err:
                        print(f"Error parsing API response: {str(parse_err)}")
                        print(f"Raw response: {response.content.decode()[:500]}")
                        flash(f"Error: Could not add beneficiary. Status code: {response.status_code}", 'danger')
                    
                    return render_template('add_beneficiary.html', vault=vault, beneficiaries=beneficiaries)
            except Exception as e:
                print(f"Exception in frontend_add_beneficiary: {str(e)}")
                import traceback
                print(traceback.format_exc())
                flash(f"Error: {str(e)}", 'danger')
                return render_template('add_beneficiary.html', vault=vault, beneficiaries=beneficiaries)
        
        # GET request - display the form
        return render_template('add_beneficiary.html', vault=vault, beneficiaries=beneficiaries)

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
        """Request access to a vault by providing multiple beneficiary shares."""
        import secrets
        
        # Find the vault
        vault = Vault.query.filter_by(vault_id=vault_id).first()
        if not vault:
            flash('Vault not found.', 'danger')
            return redirect(url_for('frontend_beneficiary_access'))
        
        if request.method == 'POST':
            # Get all submitted usernames and shares
            usernames = request.form.getlist('usernames[]')
            shares = request.form.getlist('shares[]')
            
            # Validate input
            if not usernames or not shares or len(usernames) != len(shares):
                flash('Invalid request. Please provide matching usernames and shares.', 'danger')
                return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
            
            # Check for empty values
            if any(not username.strip() for username in usernames) or any(not share.strip() for share in shares):
                flash('All username and share fields must be filled.', 'danger')
                return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
            
            # Check if the dead man's switch has been triggered
            switch = DeadMansSwitch.query.filter_by(user_id=vault.user_id).first()
            if not switch or switch.status != 'triggered':
                flash('Access to this vault is not available at this time.', 'danger')
                return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
            
            # Generate request ID
            request_id = secrets.token_hex(16)
            
            # Log event
            from audit import log_event
            log_event(None, "access_requested", {
                "vault_id": vault_id,
                "beneficiary_count": len(usernames)
            })
            
            # Reconstruct the secret
            try:
                # Get the system share
                system_share = KeyShare.query.filter_by(vault_id=vault.id, share_type="system").first()
                
                # Verify we have the system share
                if not system_share:
                    flash('Error: System share not found.', 'danger')
                    return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
                
                # Decrypt the system share
                share_data = json.loads(system_share.encrypted_share)
                salt = base64.b64decode(share_data['salt'])

                share_key, _ = create_share_key(
                    system_share.share_index, 
                    vault_id, 
                    "system_share",
                    salt
                )

                decrypted_system_share = decrypt_data(share_data['share'], share_key)
                
                # Prepare shares for reconstruction
                shares_for_reconstruction = [
                    (system_share.share_index, decrypted_system_share)
                ]
                
                # Look up each beneficiary and add their share with the correct index
                beneficiary_names = []
                
                for i, (username, share_value) in enumerate(zip(usernames, shares)):
                    # Find the beneficiary
                    beneficiary = Beneficiary.query.filter_by(vault_id=vault.id, username=username.strip()).first()
                    
                    if not beneficiary:
                        flash(f'Beneficiary "{username}" is not registered for this vault.', 'danger')
                        return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
                    
                    # Get the correct share index
                    if not beneficiary.key_share:
                        flash(f'Share information missing for beneficiary "{username}".', 'danger')
                        return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
                    
                    # Add to our list with the correct index
                    share_index = beneficiary.key_share.share_index
                    shares_for_reconstruction.append((share_index, share_value.strip()))
                    
                    # Collect beneficiary names for display
                    beneficiary_names.append(username)
                    
                    # Debug info
                    print(f"Added share for beneficiary {username} with index {share_index}")
                
                # Check if we have enough shares to meet the threshold
                if len(shares_for_reconstruction) < vault.threshold:
                    flash(f'Not enough shares provided. You need at least {vault.threshold}, but only provided {len(shares_for_reconstruction) - 1} beneficiary shares.', 'warning')
                    return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
                
                # Debug output
                print(f"Reconstructing secret with {len(shares_for_reconstruction)} shares (threshold={vault.threshold})")
                for i, (idx, _) in enumerate(shares_for_reconstruction):
                    print(f"  Share {i}: index={idx}")
                
                # We have enough shares, reconstruct the secret
                try:
                    secret = ShamirSecretSharing.reconstruct_secret(
                        shares_for_reconstruction, 
                        vault.threshold
                    )
                    
                    # Success! Return the reconstructed key
                    return render_template(
                        'access_granted.html',
                        vault_id=vault_id,
                        username=", ".join(beneficiary_names),
                        request_id=request_id,
                        secret=secret
                    )
                except ValueError as e:
                    # If reconstruction fails, show a helpful error
                    print(f"Secret reconstruction failed: {str(e)}")
                    flash('Unable to reconstruct the vault secret. Please verify your share values.', 'danger')
                    return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
                    
            except Exception as e:
                # Log the error
                import traceback
                print(f"Error reconstructing secret: {str(e)}")
                print(traceback.format_exc())
                flash('An error occurred while retrieving the key. Please check your share values.', 'danger')
                return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)
        
        # GET request - display the form
        return render_template('request_access.html', vault_id=vault_id, threshold=vault.threshold)