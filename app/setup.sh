#!/bin/bash
# Setup script for the Key Escrow Service

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file..."
    cp .env.example .env
    
    # Generate a secure random key for SECRET_KEY
    SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
    # Update the SECRET_KEY in .env
    sed -i "s/your-secure-secret-key-here/$SECRET_KEY/" .env
fi

# Create data directory if it doesn't exist
if [ ! -d data ]; then
    echo "Creating data directory..."
    mkdir -p data
fi

echo "Setup complete. You can now run the application with:"
echo "  source venv/bin/activate"
echo "  python run.py"