"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Dead man's switch implementation
"""

from datetime import datetime, timedelta

from flask import Flask

from app import db
from audit import log_event
from models import DeadMansSwitch, User


def check_dead_mans_switches(app: Flask) -> None:
    """
    Check all dead man's switches and take appropriate action.
    
    This function should be called periodically by a scheduler.
    
    Args:
        app: Flask application context
    """
    with app.app_context():
        # Get all active users with their check-in intervals
        users = User.query.all()
        
        for user in users:
            # Calculate when the user should have checked in
            check_in_deadline = user.last_check_in + timedelta(days=user.check_in_interval)
            
            # If the deadline has passed
            if datetime.utcnow() > check_in_deadline:
                # Get the user's dead man's switch
                switch = DeadMansSwitch.query.filter_by(user_id=user.id).first()
                
                if not switch:
                    # Create a switch if it doesn't exist
                    switch = DeadMansSwitch(user_id=user.id, status='active', alert_stage=0)
                    db.session.add(switch)
                    db.session.commit()
                
                # If the switch is active and the user hasn't checked in
                if switch.status == 'active':
                    # Progress through the alert stages
                    progress_switch_alert_stage(switch, user.id)


def progress_switch_alert_stage(switch: DeadMansSwitch, user_id: int) -> None:
    """
    Progress the dead man's switch to the next alert stage.
    
    Args:
        switch: The dead man's switch object
        user_id: The ID of the user who owns the switch
    """
    if switch.alert_stage == 0:
        # First stage: notify the user
        switch.alert_stage = 1
        switch.last_notified = datetime.utcnow()
        switch.grace_period_end = datetime.utcnow() + timedelta(days=3)
        db.session.commit()
        
        # Send notification to the user (email or other method)
        # This is a stub for the prototype
        # send_user_notification(user_id, "dead_mans_switch_warning")
        
        # Log the event
        log_event(user_id, "dead_mans_switch_stage1", {"user_id": user_id})
        
    #TODO: Put back in the day delay between switch activations
    elif switch.alert_stage == 1: #and datetime.utcnow() > switch.grace_period_end:
        # Second stage: notify beneficiaries
        switch.alert_stage = 2
        switch.last_notified = datetime.utcnow()
        switch.grace_period_end = datetime.utcnow() + timedelta(days=4)
        db.session.commit()
        
        # Send notifications to beneficiaries
        # This is a stub for the prototype
        # notify_beneficiaries(user_id, "dead_mans_switch_warning")
        
        # Log the event
        log_event(user_id, "dead_mans_switch_stage2", {"user_id": user_id})
    
    elif switch.alert_stage == 2: #and datetime.utcnow() > switch.grace_period_end:
        # Final stage: activate access for beneficiaries
        switch.alert_stage = 3
        switch.status = 'triggered'
        switch.last_notified = datetime.utcnow()
        db.session.commit()
        
        # Activate access for beneficiaries
        # This is a stub for the prototype
        # activate_beneficiary_access(user_id)
        
        # Log the event
        log_event(user_id, "dead_mans_switch_triggered", {"user_id": user_id})


def reset_dead_mans_switch(user_id: int) -> bool:
    """
    Reset a user's dead man's switch to the active, no-alert state.
    
    Args:
        user_id: The ID of the user
        
    Returns:
        True if the switch was reset, False if it was already triggered
    """
    switch = DeadMansSwitch.query.filter_by(user_id=user_id).first()
    
    if not switch:
        # Create a new switch if it doesn't exist
        switch = DeadMansSwitch(user_id=user_id, status='active', alert_stage=0)
        db.session.add(switch)
        db.session.commit()
        return True
    
    # If the switch is already triggered, it cannot be reset
    if switch.status == 'triggered':
        return False
    
    # Reset the switch
    switch.alert_stage = 0
    switch.last_notified = None
    switch.grace_period_end = None
    db.session.commit()
    
    # Log the event
    log_event(user_id, "dead_mans_switch_reset", {})
    
    return True