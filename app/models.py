"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Database models
"""

from datetime import datetime
from app import db

class User(db.Model):
    """User model representing vault owners and administrators."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=False)
    last_check_in = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    check_in_interval = db.Column(db.Integer, nullable=False, default=7)  # days
    vaults = db.relationship('Vault', backref='owner', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'


class Vault(db.Model):
    """Vault model representing a collection of secure key shares."""
    id = db.Column(db.Integer, primary_key=True)
    vault_name = db.Column(db.String(64), unique=True, nullable=False)
    vault_id = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # New fields for threshold management
    threshold = db.Column(db.Integer, nullable=False, default=2)
    total_shares = db.Column(db.Integer, nullable=False, default=2)
    shares = db.relationship('KeyShare', backref='vault', lazy=True)
    beneficiaries = db.relationship('Beneficiary', backref='vault', lazy=True)
    
    def __repr__(self):
        return f'<Vault {self.vault_id}>'


class KeyShare(db.Model):
    """KeyShare model for storing encrypted Shamir's Secret Sharing pieces."""
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey('vault.id'), nullable=False)
    encrypted_share = db.Column(db.Text, nullable=False)
    share_index = db.Column(db.Integer, nullable=False)
    # New field to identify share type: "system", "owner", "beneficiary"
    share_type = db.Column(db.String(20), nullable=False, default="system")
    # For beneficiary shares, link to the beneficiary
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'), nullable=True)
    
    def __repr__(self):
        return f'<KeyShare {self.id} for Vault {self.vault_id}>'


class Beneficiary(db.Model):
    """Beneficiary model for users who can access the vault when the dead man's switch is triggered."""
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, db.ForeignKey('vault.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    notification_email = db.Column(db.String(120), nullable=False)
    threshold_index = db.Column(db.Integer, nullable=False)
    # Add relationship to key share
    key_share = db.relationship('KeyShare', backref='beneficiary', uselist=False)
    # Add field to store the temporary share display status
    share_displayed = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Beneficiary {self.username} for Vault {self.vault_id}>'


class AuditLog(db.Model):
    """Tamper-evident audit log with hash chaining for security events."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)
    event_data = db.Column(db.Text, nullable=True)
    hash_prev = db.Column(db.String(64), nullable=True)
    hash_current = db.Column(db.String(64), nullable=False)
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.event_type}>'


class DeadMansSwitch(db.Model):
    """Dead man's switch status tracking for vault owners."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='active')
    alert_stage = db.Column(db.Integer, nullable=False, default=0)
    last_notified = db.Column(db.DateTime, nullable=True)
    grace_period_end = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<DeadMansSwitch {self.id} for User {self.user_id}: {self.status}>'