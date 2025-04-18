# Zero Trust Key Escrow Service with Dead Man's Switch

This is a prototype implementation of a secure zero-trust key escrow service with a dead man's switch. It's designed to securely store and manage cryptographic keys that can be released to designated beneficiaries under specific conditions.

## Features

- **Zero Trust Architecture**: Never trusts, always verifies
- **Shamir's Secret Sharing**: Split keys into multiple shares with a threshold for reconstruction
- **Two-Factor Authentication**: Password + TOTP verification
- **Dead Man's Switch**: Automatically release keys if the owner fails to check in
- **Tamper-Evident Logging**: Hash-chained audit logs for security events
- **Secure Cryptography**: NaCl for authenticated encryption
- **Web Frontend**: Clean, responsive UI for easy management of keys and beneficiaries

## Project Structure

- `app.py`: Main application entry point
- `models.py`: Database models
- `auth.py`: Authentication utilities
- `crypto.py`: Cryptography utilities
- `dead_mans_switch.py`: Dead man's switch implementation
- `routes.py`: API endpoints
- `frontend_routes.py`: Web UI routes
- `audit.py`: Audit logging system
- `templates/`: HTML templates for the web interface
- `static/`: CSS, JavaScript, and image files for the frontend

## Security Design

1. **Key Storage**: Keys are split using Shamir's Secret Sharing and encrypted
2. **Authentication**: Multiple factors required (password, TOTP)
3. **Dead Man's Switch**: Multi-stage activation with notification periods
4. **Audit Trail**: Tamper-evident logging with hash chaining

## Setup and Installation

### Prerequisites

- Python 3.9+
- pip

### Local Development

1. Clone the repository:
   ```
   git clone https://github.com/brentkastner/keybutler.git
   cd keybutler
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file:
   ```
   cp .env.example .env
   ```
   Edit the `.env` file to update settings as needed.

5. Run the application:
   ```
   python run.py
   ```

6. Access the web interface at http://localhost:5000

### Docker Deployment

1. Build and run with Docker Compose:
   ```
   docker-compose up -d
   ```

2. Access the web interface at http://localhost:5000

## Web Interface

The application includes a complete web interface that allows users to:

- Register and log in with two-factor authentication
- Create and manage vaults for storing diceware keyphrase
- Add and manage beneficiaries who can access vault contents
- Configure dead man's switch settings
- Perform regular check-ins to prevent switch activation
- Access vault contents as a beneficiary (when the switch is triggered)

## API Endpoints

For programmatic access, the service also provides a RESTful API:

### Authentication

- `POST /api/register`: Register a new user
- `POST /api/login`: Login with username and password
- `POST /api/verify-totp`: Verify TOTP code
- `POST /api/logout`: Logout user
- `POST /api/check-in`: Perform a check-in to reset the dead man's switch

### Vault Management

- `POST /api/vault`: Create a new vault
- `GET /api/vaults`: List all vaults for the user
- `GET /api/vault/<vault_id>`: Get vault details

### Beneficiary Management

- `POST /api/beneficiary`: Add a beneficiary to a vault
- `DELETE /api/beneficiary/<beneficiary_id>`: Remove a beneficiary

### Dead Man's Switch

- `POST /api/setup-dead-mans-switch`: Configure dead man's switch settings

### Beneficiary Access

- `POST /api/request-access/<vault_id>`: Request access as a beneficiary
- `POST /api/retrieve-key/<vault_id>`: Retrieve the key as a beneficiary

## Web Interface

### Main Pages

- **Home**: Landing page with service information
- **Register/Login**: User authentication with TOTP setup
- **Dashboard**: Overview of vaults and dead man's switch status
- **Vault Management**: Create and view vaults, manage key shares
- **Beneficiary Management**: Add and manage beneficiaries
- **Switch Settings**: Configure dead man's switch parameters
- **Beneficiary Access Portal**: Interface for beneficiaries to request access

### Security Features

- **Two-Factor Authentication**: TOTP integration for secure login
- **Client-Side Validation**: Password strength meters and input validation
- **Visual Status Indicators**: Clear indicators for switch status and check-in deadlines
- **Responsive Design**: Works on desktop and mobile devices

## Screenshots

(Screenshots would be included here in a production README)

## Development

### Adding New Features

1. Add routes in `frontend_routes.py` or `routes.py`
2. Create templates in the `templates/` directory
3. Add static assets in the `static/` directory

### Running Tests

```
python -m unittest test_app.py
```

## Warning

This is a prototype implementation intended for educational purposes. While it implements many security best practices, it has not undergone formal security auditing and should not be used in production environments without extensive review and hardening.

## License

This project is licensed under the MIT License - see the LICENSE file for details.