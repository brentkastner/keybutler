#!/usr/bin/env python
"""
Set Check-in Tool for Key Escrow Service
----------------------------------------
This script artificially sets a user's last check-in date to test the dead man's switch.
Usage: python set_checkin.py <username> <days_ago>
"""

import os
import sys
from datetime import datetime, timedelta
from flask import Flask

# Check if the correct number of arguments is provided
if len(sys.argv) < 3:
    print("Usage: python set_checkin.py <username> <days_ago>")
    sys.exit(1)

# Get command line arguments
username = sys.argv[1]
try:
    days_ago = int(sys.argv[2])
except ValueError:
    print("Error: days_ago must be a number")
    sys.exit(1)

# Import the Flask app and database
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Create a Flask app context
from app import app, db
from models import User, DeadMansSwitch

# Run the manipulation inside the app context
with app.app_context():
    print(f"Looking for user '{username}'...")
    
    # Find the user
    user = User.query.filter_by(username=username).first()
    if not user:
        print(f"Error: User '{username}' not found")
        sys.exit(1)
    
    # Calculate and set the new last check-in time
    original_check_in = user.last_check_in
    new_check_in = datetime.utcnow() - timedelta(days=days_ago)
    user.last_check_in = new_check_in
    
    # Commit the change
    db.session.commit()
    
    print(f"Updated user '{username}' (ID: {user.id}):")
    print(f"  - Original last check-in: {original_check_in}")
    print(f"  - New last check-in:      {new_check_in}")
    print(f"  - Check-in interval:      {user.check_in_interval} days")
    
    # Check switch status
    switch = DeadMansSwitch.query.filter_by(user_id=user.id).first()
    if switch:
        print(f"  - Current switch status:  {switch.status}")
        print(f"  - Current alert stage:    {switch.alert_stage}")
    else:
        print("  - No dead man's switch found for this user")
    
    print("\nTo trigger the switch check, restart the server or wait for the scheduled check.")
    print("You can also run the check manually with a separate script.")
    
    # Optionally run the check immediately
    run_check = input("\nWould you like to run the dead man's switch check now? (y/n): ")
    if run_check.lower() == 'y':
        from dead_mans_switch import check_dead_mans_switches
        print("Running dead man's switch check...")
        check_dead_mans_switches(app)
        
        # Check new status
        switch = DeadMansSwitch.query.filter_by(user_id=user.id).first()
        if switch:
            print(f"  - New switch status:  {switch.status}")
            print(f"  - New alert stage:    {switch.alert_stage}")
        
        print("\nCheck complete. Log in to the application to see the effects.")