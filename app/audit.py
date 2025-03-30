"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Tamper-evident audit logging system with hash chaining
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Optional

from app import db
from models import AuditLog


def log_event(user_id: Optional[int], event_type: str, event_data: Optional[Dict] = None) -> None:
    """
    Log an event to the audit log with hash chaining for tamper evidence.
    
    Args:
        user_id: The ID of the user associated with the event, or None
        event_type: The type of event (e.g., "user_login", "vault_created")
        event_data: Optional dictionary of additional event data
    """
    # Get the hash of the previous log entry
    last_log = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = last_log.hash_current if last_log else None
    
    # Create the log data
    log_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user_id,
        "event_type": event_type,
        "event_data": json.dumps(event_data) if event_data else None,
        "prev_hash": prev_hash
    }
    
    # Calculate the hash for this entry
    # We use the sorted keys to ensure consistency
    current_hash = hashlib.sha256(json.dumps(log_data, sort_keys=True).encode()).hexdigest()
    
    # Create and save the log entry
    log_entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        event_data=log_data.get("event_data"),
        hash_prev=prev_hash,
        hash_current=current_hash
    )
    db.session.add(log_entry)
    db.session.commit()


def verify_audit_log_integrity() -> bool:
    """
    Verify the integrity of the audit log chain.
    
    Returns:
        True if the audit log chain is intact, False if tampering is detected
    """
    logs = AuditLog.query.order_by(AuditLog.id).all()
    
    prev_hash = None
    for log in logs:
        # Reconstruct the data that went into the hash
        log_data = {
            "timestamp": log.timestamp.isoformat(),
            "user_id": log.user_id,
            "event_type": log.event_type,
            "event_data": log.event_data,
            "prev_hash": log.hash_prev
        }
        
        # Verify that the previous hash matches
        if log.hash_prev != prev_hash:
            return False
        
        # Calculate the hash and verify it matches
        calculated_hash = hashlib.sha256(json.dumps(log_data, sort_keys=True).encode()).hexdigest()
        if calculated_hash != log.hash_current:
            return False
        
        # Set this hash as the previous hash for the next iteration
        prev_hash = log.hash_current
    
    return True


def get_audit_logs_for_user(user_id: int, limit: int = 100) -> list:
    """
    Get recent audit logs for a specific user.
    
    Args:
        user_id: The ID of the user
        limit: Maximum number of logs to return
        
    Returns:
        List of audit log entries as dictionaries
    """
    logs = AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    result = []
    for log in logs:
        log_data = {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "event_type": log.event_type,
            "event_data": json.loads(log.event_data) if log.event_data else None
        }
        result.append(log_data)
    
    return result