"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Simple test script to validate the application
"""

import json
import unittest
import base64
from datetime import datetime, timedelta

from app import app, db
from models import User, Vault, KeyShare, DeadMansSwitch, Beneficiary
from auth import generate_totp_secret, verify_totp
from crypto import ShamirSecretSharing
from werkzeug.security import generate_password_hash


class KeyEscrowTestCase(unittest.TestCase):
    """Test cases for the Key Escrow Service."""

    def setUp(self):
        """Set up test environment."""
        # Configure the app for testing
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['SECRET_KEY'] = 'test-key'
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF protection for testing
        app.config['SERVER_NAME'] = 'localhost'  # Set server name for URL generation
        app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem sessions for testing
        
        # Create an app context
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Create all tables
        db.create_all()
        
        # Create a test client with persistent sessions
        self.client = app.test_client(use_cookies=True)
        self.client.testing = True
        
        # Add test data
        self.setup_test_data()

    def tearDown(self):
        """Tear down test environment."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def setup_test_data(self):
        """Create test data for the tests."""
        # Create a test user
        totp_secret = generate_totp_secret()
        test_user = User(
            username="testuser",
            password_hash=generate_password_hash("testpassword"),
            totp_secret=totp_secret,
            last_check_in=datetime.utcnow(),
            check_in_interval=7
        )
        db.session.add(test_user)
        db.session.commit()
        
        # Save the user ID and TOTP secret for testing
        self.test_user_id = test_user.id
        self.test_totp_secret = totp_secret
        
        # Create a dead man's switch for the user
        test_switch = DeadMansSwitch(
            user_id=test_user.id,
            status='active',
            alert_stage=0
        )
        db.session.add(test_switch)
        db.session.commit()

    def login(self):
        """Helper function to log in the test user."""
        # First, log in with username and password
        response = self.client.post(
            '/api/login',
            json={"username": "testuser", "password": "testpassword"},
            content_type='application/json'
        )
        
        print(f"Login response status: {response.status_code}")
        print(f"Login response data: {response.data}")
        
        if response.status_code != 200:
            # If login fails, print detailed error for debugging
            print("Login failed. Checking if user exists in database...")
            user = User.query.filter_by(username="testuser").first()
            if user:
                print(f"User found: {user.username}, ID: {user.id}")
                print(f"Password hash: {user.password_hash}")
            else:
                print("User 'testuser' not found in database!")
            self.fail("Login failed")
        
        # Check that session was set correctly
        with self.client.session_transaction() as sess:
            print(f"Session after login: {dict(sess)}")
            self.assertIn('user_id', sess, "user_id not in session after login")
            user_id = sess['user_id']
            
            # Get the user for TOTP verification
            user = db.session.get(User, user_id)
            if not user:
                self.fail(f"User with ID {user_id} not found in database")
                
            # Manually set TOTP verified since we're simulating this
            sess['totp_verified'] = True
            
        return True  # Login successful

    def test_registration(self):
        """Test user registration."""
        response = self.client.post(
            '/api/register',
            json={"username": "newuser", "password": "newpassword"}
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn("totp_secret", data)
        
        # Verify the user exists in the database
        user = User.query.filter_by(username="newuser").first()
        self.assertIsNotNone(user)

    def test_login_and_check_in(self):
        """Test login process and check-in."""
        self.login()
        
        # Test check-in
        response = self.client.post(
            '/api/check-in',
            content_type='application/json'
        )
        
        print(f"Check-in response status: {response.status_code}")
        print(f"Check-in response data: {response.data}")
        
        if response.status_code != 200:
            with self.client.session_transaction() as sess:
                print(f"Session during check-in: {dict(sess)}")
                
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("next_check_in_required", data)

    def test_create_vault(self):
        """Test creating a new vault."""
        self.login()
        
        # Create a new vault
        vault_data = {
            "vault_id": "test-vault-1",
            "diceware_keyphrase": "correct horse battery staple",
            "num_shares": 3,
            "threshold": 2
        }
        
        response = self.client.post(
            '/api/vault',
            json=vault_data,
            content_type='application/json'
        )
        
        print(f"Create vault response status: {response.status_code}")
        print(f"Create vault response data: {response.data}")
        
        if response.status_code != 201:
            with self.client.session_transaction() as sess:
                print(f"Session during vault creation: {dict(sess)}")
                
        self.assertEqual(response.status_code, 201)
        
        # Verify the vault exists
        vault = Vault.query.filter_by(vault_id="test-vault-1").first()
        self.assertIsNotNone(vault)
        
        # Verify the shares were created
        shares = KeyShare.query.filter_by(vault_id=vault.id).all()
        self.assertEqual(len(shares), 3)

    def test_add_beneficiary(self):
        """Test adding a beneficiary to a vault."""
        self.login()
        
        # First create a vault
        vault_response = self.client.post(
            '/api/vault',
            json={
                "vault_id": "test-vault-2",
                "diceware_keyphrase": "correct horse battery staple",
                "num_shares": 3,
                "threshold": 2
            },
            content_type='application/json'
        )
        
        print(f"Create vault for beneficiary test response: {vault_response.status_code}")
        
        if vault_response.status_code != 201:
            with self.client.session_transaction() as sess:
                print(f"Session during vault creation for beneficiary test: {dict(sess)}")
            print(f"Vault response data: {vault_response.data}")
            self.fail("Vault creation failed in beneficiary test")
            
        # Add a beneficiary
        beneficiary_data = {
            "vault_id": "test-vault-2",
            "username": "beneficiary1",
            "email": "beneficiary1@example.com",
            "public_key": "mock-public-key",
            "threshold_index": 1
        }
        
        response = self.client.post(
            '/api/beneficiary',
            json=beneficiary_data,
            content_type='application/json'
        )
        
        print(f"Add beneficiary response: {response.status_code}")
        if response.status_code != 201:
            print(f"Response data: {response.data}")
            with self.client.session_transaction() as sess:
                print(f"Session during beneficiary creation: {dict(sess)}")
        
        self.assertEqual(response.status_code, 201)
        
        # Verify the beneficiary exists
        vault = Vault.query.filter_by(vault_id="test-vault-2").first()
        self.assertIsNotNone(vault, "Vault not found after creation")
        
        beneficiary = Beneficiary.query.filter_by(vault_id=vault.id).first()
        self.assertIsNotNone(beneficiary, "Beneficiary not found after creation")
        self.assertEqual(beneficiary.username, "beneficiary1")

    def test_dead_mans_switch(self):
        """Test the dead man's switch activation."""
        # Update the user's last check-in to be more than the interval ago
        user = db.session.get(User, self.test_user_id)
        user.last_check_in = datetime.utcnow() - timedelta(days=user.check_in_interval + 1)
        db.session.commit()
        
        # Trigger the switch check manually (normally done by the scheduler)
        from dead_mans_switch import check_dead_mans_switches
        check_dead_mans_switches(app)
        
        # Check that the switch is in alert stage 1
        switch = DeadMansSwitch.query.filter_by(user_id=self.test_user_id).first()
        self.assertEqual(switch.alert_stage, 1)
        
        # Simulate the grace period ending
        switch.grace_period_end = datetime.utcnow() - timedelta(hours=1)
        db.session.commit()
        
        # Check again
        check_dead_mans_switches(app)
        
        # Should be in alert stage 2
        switch = DeadMansSwitch.query.filter_by(user_id=self.test_user_id).first()
        self.assertEqual(switch.alert_stage, 2)
        
        # Simulate the second grace period ending
        switch.grace_period_end = datetime.utcnow() - timedelta(hours=1)
        db.session.commit()
        
        # Check one more time
        check_dead_mans_switches(app)
        
        # Should be triggered
        switch = DeadMansSwitch.query.filter_by(user_id=self.test_user_id).first()
        self.assertEqual(switch.status, 'triggered')

    def test_secret_sharing(self):
        """Test Shamir's Secret Sharing implementation."""
        secret = "This is a secret message"
        n = 5  # number of shares
        t = 3  # threshold
        
        # Create shares
        shares = ShamirSecretSharing.create_shares(secret, n, t)
        self.assertEqual(len(shares), n)
        
        # Reconstruct with exactly t shares
        subset = shares[:t]
        reconstructed = ShamirSecretSharing.reconstruct_secret(subset, t)
        self.assertEqual(reconstructed, secret)
        
        # Try with more than t shares
        subset = shares[:t+1]
        reconstructed = ShamirSecretSharing.reconstruct_secret(subset, t)
        self.assertEqual(reconstructed, secret)
        
        # Should fail with less than t shares
        subset = shares[:t-1]
        with self.assertRaises(ValueError):
            ShamirSecretSharing.reconstruct_secret(subset, t)


if __name__ == '__main__':
    unittest.main()