"""
Key Escrow Service with Dead Man's Switch - Prototype
----------------------------------------------------
Main application entry point
"""
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler

load_dotenv()
# Initialize Flask application
app = Flask(__name__)

# Load configuration from environment variables
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URI", "sqlite:///escrow_service.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=120)  # Short-lived sessions

# Initialize database
db = SQLAlchemy(app)

# Import models and other components after initializing app and db
from models import User, Vault, KeyShare, Beneficiary, AuditLog, DeadMansSwitch
from routes import register_routes
from frontend_routes import register_frontend_routes
from dead_mans_switch import check_dead_mans_switches

# Register API routes
register_routes(app)

# Register frontend routes
register_frontend_routes(app, db)

# Initialize scheduler for dead man's switch check
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_dead_mans_switches, trigger="interval", seconds=30, args=[app])
scheduler.start()

# Add template context processors
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Create database tables - instead of using before_first_request
with app.app_context():
    db.create_all()

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

if __name__ == "__main__":
    # Run the application
    app.run(
        host=os.environ.get("HOST", "0.0.0.0"),
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("DEBUG", "False").lower() == "true"
    )