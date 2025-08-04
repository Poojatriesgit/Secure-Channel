# Secure Banking Communication System

A Python-based secure messaging platform with dual CLI interfaces for customers and bank administrators. Features AES encryption, RSA digital signatures, location tracking, and network analysis for secure banking communications.
<img width="684" height="746" alt="image" src="https://github.com/user-attachments/assets/a04aa96c-c0f2-421c-be49-ee80230ccdfb" />

## Features

- **End-to-End Encryption** - AES encryption using Fernet for message content
- **Digital Signatures** - RSA-2048 digital signatures for message authenticity
- **Dual Interface** - Separate CLI applications for customers and bank staff
- **Location Tracking** - Real-time IP-based location data for security auditing
- **Network Analysis** - Latency monitoring and connection metrics
- **Secure Storage** - SQLite database with encrypted message storage
- **Message Verification** - Digital signature verification for tamper detection
- **Cross-Platform** - Compatible with Windows, macOS, and Linux
  <img width="682" height="372" alt="image" src="https://github.com/user-attachments/assets/a5f4dc66-5bf6-4bdb-82af-da73704ea6bb" />


## Prerequisites

- Python 3.7 or higher
- Internet connection (for location services and network latency testing)

## Required Dependencies

```bash
pip install cryptography requests
```

## Installation

1. Clone or download the repository
2. Install the required dependencies:
   ```bash
   pip install cryptography requests
   ```
3. Update the `STORAGE_PATH` in both files to your desired data directory:
   ```python
   STORAGE_PATH = r"C:\path\to\your\data\directory"  # Windows
   STORAGE_PATH = "/path/to/your/data/directory"     # Linux/macOS
   ```

## Usage

### Customer Interface (gc_cli.py)

Run the customer application:
```bash
python gc_cli.py
```

**Features:**
- User registration with automatic key generation
- Secure login with password hashing
- Send encrypted and digitally signed messages to the bank
- View message history with security status
- Message signature verification

**Menu Options:**
1. **Login** - Access existing account
2. **New User** - Register new customer account
3. **Exit** - Close application

### Bank Interface (gcbank.py)

Run the bank administration application:
```bash
python gcbank.py
```

**Features:**
- Bank administrator account management
- View all customer messages with metadata
- Decrypt and verify customer messages
- Send digitally signed responses to customers
- View sent responses and banking statistics
- Customer management and system analytics

**Menu Options:**
1. **Bank Administrator Login** - Access admin panel
2. **Create New Bank Administrator** - Add new admin user
3. **Exit** - Close application

**Admin Panel Features:**
1. View customer messages overview
2. Decrypt and verify specific customer messages
3. Send digitally signed responses to customers
4. View sent responses history
5. View bank's public key
6. View all registered customers
7. Banking system statistics
8. Logout

## File Structure

```
secure-banking-system/
├── gc_cli.py              # Customer CLI interface
├── gcbank.py              # Bank CLI interface
├── README.md              # This file
└── data/                  # Data directory (created automatically)
    ├── banking_system.db  # SQLite database
    ├── user_messages/     # Encrypted customer messages
    │   └── [user_id]/     # User-specific message folders
    └── bank_responses/    # Bank response files
        └── [user_id]/     # Customer-specific response folders
```

## Security Features

### Encryption
- **AES Encryption**: Message content encrypted using Fernet (AES 128 in CBC mode)
- **Key Management**: Unique encryption keys per user, stored securely in database
- **RSA Key Pairs**: 2048-bit RSA keys for digital signatures

### Authentication
- **Password Hashing**: SHA-256 password hashing
- **Digital Signatures**: RSA-PSS signatures with SHA-256
- **Message Integrity**: Hash verification for message and metadata

### Privacy & Security
- **Location Privacy**: IP-based location tracking for security auditing
- **Network Monitoring**: Latency tracking for anomaly detection
- **Secure Storage**: All sensitive data encrypted at rest
- **Signature Verification**: Tamper detection through signature validation

## Database Schema

### Users Table
- User credentials and encryption keys
- Registration location and network data
- Public/private key pairs

### Messages Table
- Encrypted message files and metadata
- Network latency and location data
- Digital signatures and verification status

### Bank Administrators Table
- Admin credentials and department information
- Login tracking and access control

### Bank Keys Table
- Bank's RSA key pairs for digital signatures
- Key versioning and management

### Bank Responses Table
- Response tracking and digital signatures
- Customer correlation and admin attribution

## Network Requirements

The application requires internet access for:
- **Location Services**: IP geolocation via multiple API services
- **Network Testing**: Latency measurement using ping and HTTP requests
- **Time Synchronization**: Timestamp generation for messages

## Error Handling

- Graceful handling of network failures
- Fallback mechanisms for location services
- Database integrity checks
- Key generation failure recovery
- Message encryption/decryption error handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Security Considerations

- Change default storage paths in production
- Implement proper key backup and recovery
- Use secure password policies
- Monitor for suspicious network activity
- Regular security audits recommended

## License

This project is provided as-is for educational and demonstration purposes. Please ensure compliance with local banking and encryption regulations before production use.

## Disclaimer

This is a demonstration system for educational purposes. For production banking applications, additional security measures, compliance with banking regulations, and professional security auditing are required.
