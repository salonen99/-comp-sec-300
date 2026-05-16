# Secure Password Manager

A locally hosted, Windows Presentation Foundation (WPF) Password Manager designed to securely store, retrieve, and generate cryptographic credentials with an intuitive graphical interface.

This project was developed with strict adherence to secure programming principles and the OWASP Top 10 framework. It serves as a foundational architecture for understanding secure data persistence, cryptographic key derivation, authenticated encryption, and multi-factor authentication (MFA) integration.

## Core Features

**Cryptographic Security**
- Utilizes **AES-256-GCM** for authenticated encryption of all stored passwords and vault data
- Implements **Argon2id** for memory-hard Master Key derivation with collision-resistant salt generation
- Enforces cryptographic random number generation (CSPRNG) for all entropy-critical operations

**In-Memory Safety**
- Implements forced session termination protocol to prevent state desynchronization
- Securely clears sensitive data from memory using zeroing patterns
- Prevents stale cache memory leaks through strict session management

**Secure Clipboard Integration**
- Automatic clipboard clearing feature that securely wipes passwords after 15 seconds of copy
- Prevents accidental credential exposure from persistent clipboard history
- Works seamlessly with Windows clipboard API

**Password Generation & Customization**
- Generate strong, cryptographically-secure passwords on-demand
- **Customizable character set selection**: Choose to include/exclude uppercase, lowercase, digits, and symbols
- **Configurable password length**: 16-128 characters (default: 32)
- **Ambiguous character filtering**: Option to exclude easily-confused characters (0/O, 1/l/I)
- Real-time password strength meter with entropy validation
- Session-persistent generation settings

**Entropy Policy**
- Enforces mathematical entropy validation (minimum 60 bits for user passwords, 80 bits recommended)
- Rejection sampling for cryptographically uniform distribution
- Prevents weak password patterns through entropy calculation

**Multi-Factor Authentication (MFA)**
- Integrates MFA setup with TOTP (Time-based One-Time Password) support
- MFA prompt on vault unlock
- Secure MFA recovery code generation and management

**Entry Management**
- Full CRUD operations for password entries
- Category-based organization (Work, Personal, Social Media, Banking, Email, Other)
- URL, username, and notes fields for comprehensive credential storage
- Edit and delete existing entries with validation

**Data Import/Export**
- Support for importing browser-exported passwords (CSV format)
- Conflict resolution dialog for duplicate imports
- Export vault to encrypted formats for backup

**Settings & Configuration**
- Customizable password strength enforcement policies
- Session timeout configuration
- Audit logging of vault operations
- User-defined security preferences

## Prerequisites

Before you begin, ensure you have the following requirements:

- **.NET Runtime**: .NET 8.0 or higher
- **Operating System**: Windows 7 SP1 or later (WPF requirement)
- **Database**: SQLite (included with .NET runtime, no separate installation needed)

## Installation

### Restore Dependencies

```bash
dotnet restore SecurePasswordManager.slnx
```

### Build the Solution

```bash
dotnet build SecurePasswordManager.slnx --configuration Release
```

### Run the Application

```bash
dotnet run --project SecurePasswordManager.App/SecurePasswordManager.App.csproj
```

Or navigate to the build output and launch `SecurePasswordManager.App.exe`:

```bash
.\SecurePasswordManager.App\bin\Release\net8.0-windows\SecurePasswordManager.App.exe
```

## Usage

### Launching the Application

1. Run the application using the commands above
2. On first launch, you will need to write **Master Password** on the password field.
   - Enter a strong password (minimum 12 characters)
   - Confirm the password
   - then press Create Vault
   - You will be asked  to setup MFA (This can be skipped)
3. On subsequent launches, **enter your Master Password** and klick Unlock Vault

### Working with Entries

**Adding a New Entry**
1. Click the **"Add Entry"** button in the main vault window
2. Fill in the required fields:
   - **Service Name** (required)
   - **Username/Email** (required)
   - **Password** (required)
3. Optionally fill in:
   - **Website URL**
   - **Notes**
   - **Category**
4. Use the **"Generate"** button to create a strong password:
   - Click **"Password Generation Options"** to customize:
     - Adjust password length (16-128 characters, default: 32)
     - Toggle character types (uppercase, lowercase, digits, symbols)
     - Exclude ambiguous characters if needed
   - Generated password appears in the Password field
5. Click **"Save Entry"** to add to vault

**Viewing & Copying Passwords**
1. Select an entry from the vault list
2. Click **"View"** to see password (requires Master Password confirmation)
3. Click **"Copy"** to copy password to clipboard
4. Clipboard will auto-clear after 15 seconds

**Editing an Entry**
1. Select an entry and click **"Edit"**
2. Modify any fields
3. Click **"Save"** to confirm changes

**Deleting an Entry**
1. Select an entry and click **"Delete"**
2. Confirm deletion when prompted

### Importing Passwords

1. Click **"Import"** in the main window
2. Select a CSV file exported from your browser's password manager
3. The application will:
   - Parse the CSV file
   - Validate format and data
   - Show conflict resolution dialog if duplicates are detected
4. Confirm import to add entries to vault

### Exporting Vault

1. Click **"Export"** in the main window
2. Choose export format (CSV or JSON)
3. Specify output location and filename
4. Data is encrypted during export for maximum security

### Configuring Settings

1. Click **"Settings"** in the main window
2. Available options:
   - **Session Timeout**: Configure automatic vault lock duration
   - **Password Strength Enforcement**: Set minimum strength requirements for entries
   - **MFA Settings**: Enable/disable MFA for vault access
   - **Clipboard Timeout**: Adjust auto-clear duration (default 15 seconds)
3. Click **"Save"** to apply changes

### Multi-Factor Authentication (MFA)

**Setting Up MFA if not set up on creation of vault**
1. Go to **Settings** → **Security** → **Enable MFA**
2. Scan the QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, etc.)
3. Enter the 6-digit code from your app to verify setup
4. Save recovery codes in a secure location
5. MFA will be required on next vault unlock

**Using MFA**
1. Enter Master Password when prompted
2. Enter the 6-digit code from your authenticator app
3. Vault unlocks after successful authentication

### Local Vulnerability Scanning

Run the dependency vulnerability check:

```bash
dotnet list SecurePasswordManager.slnx package --vulnerable --include-transitive
```

Expected output: Zero vulnerable packages detected

### Testing

Run all unit tests:

```bash
dotnet test SecurePasswordManager.Tests/SecurePasswordManager.Tests.csproj --verbosity normal
```

Test coverage includes:
- **Cryptographic Operations**: AES-GCM encryption/decryption, key derivation, random generation
- **Password Generation**: Length validation, character type selection, entropy verification
- **Data Integrity**: Database operations, import/export validation
- **Security Features**: MFA flow, session management, memory safety

## Security Considerations

### Master Password Best Practices

- Use at least 12 characters with mixed complexity (uppercase, lowercase, numbers, symbols)
- Avoid common words, keyboard patterns, or personal information
- Do not reuse passwords from other applications
- Enable MFA for additional protection

### Secure Usage Guidelines

- Always ensure your device has up-to-date Windows security patches
- Do not share your Master Password or recovery codes
- Use the clipboard auto-clear feature (default 15 seconds)
- Lock your vault when stepping away from your computer
- Regularly export and backup your vault in a secure location

### Compliance

This project adheres to:
- **OWASP Top 10** secure development principles
- **NIST Cybersecurity Framework** guidelines
- **CWE-331** recommendations for cryptographic randomness
- **CWE-312** guidelines for data destruction

## Project Structure

```
SecurePasswordManager/
├── SecurePasswordManager.App/          # WPF GUI Application
│   ├── MainWindow.xaml(.cs)            # Main vault interface
│   ├── EntryWindow.xaml(.cs)           # Add/edit password entries
│   ├── SettingsWindow.xaml(.cs)        # Application settings
│   ├── MfaSetupDialog.xaml(.cs)        # MFA configuration
│   ├── MfaPromptDialog.xaml(.cs)       # MFA authentication prompt
│   ├── VaultWindow.xaml(.cs)           # Vault management
│   ├── SecureClipboard.cs              # Clipboard handling
│   └── AppAuthService.cs               # Authentication service
├── SecurePasswordManager.Core/         # Core cryptography & business logic
│   ├── Crypto/
│   │   ├── AesGcmEncryption.cs        # AES-256-GCM implementation
│   │   ├── KeyDerivation.cs           # Argon2id key derivation
│   │   └── SecureRandom.cs            # CSPRNG password generation
│   ├── Services/
│   │   ├── VaultService.cs            # Vault operations
│   │   ├── ExportService.cs           # Export functionality
│   │   └── ImportService.cs           # Import functionality
│   ├── Models/                         # Data models
│   ├── Database/                       # Database operations
│   └── Utils/                          # Utility functions
└── SecurePasswordManager.Tests/        # Unit tests
    ├── CryptoTests.cs                 # Cryptography tests
    ├── SecurityFeatureTests.cs        # Security feature tests
    ├── MfaTests.cs                    # MFA tests
    └── ImportExportTests.cs           # I/O tests
```

## Troubleshooting

### Application Won't Start
- Ensure .NET 8.0 runtime is installed: `dotnet --version`
- Check Windows Event Viewer for detailed error logs
- Try rebuilding: `dotnet clean` and `dotnet build`

### Password Appears Weak
- Password strength is calculated based on entropy (minimum 60 bits)
- Add more character variety (uppercase, lowercase, digits, symbols)
- Increase password length

### Clipboard Not Clearing
- Verify clipboard timeout is enabled in Settings
- Check if another application is using the clipboard
- Try manually copying again

### MFA Code Not Working
- Ensure device time is synchronized (NTP)
- Authenticator app is correctly paired with vault
- Recovery codes are available as backup

### Cannot Import Passwords
- Verify CSV format matches expected structure: Service,Username,Password
- Check for special characters or encoding issues
- Try exporting from browser in simpler CSV format


## Acknowledgments

This project was developed as an exercise in secure programming practices, incorporating industry-standard cryptographic libraries and best practices from:
- OWASP Foundation
- NIST Cybersecurity Framework
- Microsoft .NET Security Guidelines

## AI Disclaimer

AI has been used in developing this project.
AI has been used for debugging and to assist writing this readme.

---

**Last Updated**: May 2026  
