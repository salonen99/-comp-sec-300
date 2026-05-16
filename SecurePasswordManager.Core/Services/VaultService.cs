/*
 * Vault Service - Core Business Logic
 * 
 * SECURITY FEATURES:
 * - Orchestrates encryption and database operations
 * - Master password never stored, only derived key kept in memory
 * - Automatic session timeout support
 * - Secure disposal of sensitive data
 * 
 * Architecture:
 * - Uses KeyDerivation for master password -> key conversion
 * - Uses AesGcmEncryption for data encryption/decryption
 * - Uses DbManager for parameterized database operations
 * - Uses Validators for input validation
 */

using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Database;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Utils;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;

namespace SecurePasswordManager.Core.Services;

/// <summary>
/// Vault service that manages the password vault securely.
/// 
/// SECURITY NOTES:
/// - Encryption key is kept in memory only while vault is unlocked
/// - All sensitive data is encrypted before storage
/// - Input validation on all operations
/// - Implements IDisposable for secure cleanup
/// </summary>
public sealed class VaultService : IDisposable
{
    private readonly string _vaultPath;
    private DbManager? _dbManager;
    private AesGcmEncryption? _encryption;
    private KeyDerivation? _keyDerivation;
    private byte[]? _encryptionKey;
    private FileStream? _vaultFileLock;  // Phase 4: File locking for multi-instance prevention
    private MfaSettings? _mfaSettings;   // Phase 6: MFA configuration
    private MfaVerificationService? _mfaVerificationService;  // Phase 6: MFA verification
    private bool _disposed;
    
    /// <summary>
    /// Whether the vault is currently unlocked.
    /// </summary>
    public bool IsUnlocked => _encryption != null && _encryptionKey != null;
    
    /// <summary>
    /// Path to the vault file.
    /// </summary>
    public string VaultPath => _vaultPath;
    
    /// <summary>
    /// Event raised when the vault is locked.
    /// </summary>
    public event EventHandler? VaultLocked;
    
    /// <summary>
    /// Initialize vault service with vault file path.
    /// </summary>
    /// <param name="vaultPath">Path to the SQLite vault file</param>
    public VaultService(string vaultPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultPath);
        _vaultPath = vaultPath;
    }
    
    /// <summary>
    /// Check if a vault file exists.
    /// </summary>
    public bool VaultFileExists() => File.Exists(_vaultPath);
    
    /// <summary>
    /// SECURITY (CWE-277, CWE-732): Restrict vault file permissions.
    /// 
    /// Only the current user can read/write the vault file.
    /// This prevents other users from accessing vault data on multi-user systems.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void ProtectVaultFilePermissions()
    {
        if (!File.Exists(_vaultPath))
            return;
        
        try
        {
            var fileInfo = new FileInfo(_vaultPath);
            var fileSecurity = fileInfo.GetAccessControl();
            
            // SECURITY: Clear all existing permissions
            var inheritanceFlags = InheritanceFlags.None;
            var propagationFlags = PropagationFlags.None;
            var accessControlType = AccessControlType.Allow;
            
            // Remove existing ACLs
            fileSecurity.SetAccessRuleProtection(true, false);
            
            // SECURITY: Add permission only for current user (full control)
            var currentUser = WindowsIdentity.GetCurrent().User;
            if (currentUser != null)
            {
                var accessRule = new FileSystemAccessRule(
                    currentUser,
                    FileSystemRights.FullControl,
                    inheritanceFlags,
                    propagationFlags,
                    accessControlType);
                
                fileSecurity.AddAccessRule(accessRule);
            }
            
            // SECURITY: Disable inheritance to prevent parent folder permissions
            fileSecurity.SetAccessRuleProtection(true, false);
            
            // Apply the new permissions
            fileInfo.SetAccessControl(fileSecurity);
        }
        catch
        {
            // SECURITY: Don't fail if we can't set permissions
            // Log this in production, but don't expose to user
        }
    }

    
    /// <summary>
    /// Create a new vault with the given master password.
    /// 
    /// SECURITY:
    /// - Validates master password strength
    /// - Derives encryption key using Argon2id
    /// - Stores only salt and verification hash (never the password)
    /// </summary>
    public async Task CreateVaultAsync(string masterPassword)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        // SECURITY: Validate master password
        var validation = Validators.ValidateMasterPassword(masterPassword);
        if (!validation.IsValid)
        {
            throw new ArgumentException(validation.ErrorMessage, nameof(masterPassword));
        }
        
        // SECURITY: Check if vault already exists
        if (VaultFileExists())
        {
            throw new InvalidOperationException("Vault file already exists");
        }
        
        _keyDerivation = new KeyDerivation();
        
        // SECURITY: Generate salt and derive key using Argon2id
        var salt = KeyDerivation.GenerateSalt();
        _encryptionKey = _keyDerivation.DeriveKey(masterPassword, salt);
        
        // SECURITY: Create verification hash (separate from encryption key)
        var verificationHash = _keyDerivation.CreateVerificationHash(masterPassword, salt);
        
        try
        {
            // Initialize encryption with derived key
            _encryption = new AesGcmEncryption(_encryptionKey);
            
            // Initialize database
            _dbManager = new DbManager(_vaultPath);
            await _dbManager.OpenAsync();
            await _dbManager.InitializeSchemaAsync();
            
            // SECURITY: Protect vault file from other users (CWE-277, CWE-732)
            // Only available on Windows
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ProtectVaultFilePermissions();
            }
            
            // Save vault metadata
            var metadata = new VaultMetadata
            {
                Salt = salt,
                VerificationHash = verificationHash,
                CreatedAt = DateTime.UtcNow,
                LastAccessedAt = DateTime.UtcNow,
                SchemaVersion = Schema.CurrentVersion
            };
            
            await _dbManager.SaveMetadataAsync(metadata);
        }
        catch
        {
            // SECURITY: Clean up on failure
            Lock();
            
            // Delete partial vault file
            if (File.Exists(_vaultPath))
            {
                File.Delete(_vaultPath);
            }
            
            throw;
        }
    }
    
    /// <summary>
    /// Open and unlock an existing vault.
    /// 
    /// SECURITY:
    /// - Validates master password against stored verification hash
    /// - Uses constant-time comparison to prevent timing attacks
    /// </summary>
    public async Task<bool> UnlockVaultAsync(string masterPassword, Func<MfaVerificationService, Task<bool>>? mfaVerifier = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        if (!VaultFileExists())
        {
            throw new FileNotFoundException("Vault file not found", _vaultPath);
        }
        
        // SECURITY: Validate password format first
        var validation = Validators.ValidateMasterPassword(masterPassword);
        if (!validation.IsValid)
        {
            return false;
        }
        
        _keyDerivation = new KeyDerivation();
        
        // Phase 4: Acquire exclusive file lock to prevent concurrent access
        try
        {
            _vaultFileLock = VaultLock.LockVaultFile(_vaultPath);
        }
        catch (Utils.SecurityException)
        {
            // Vault file is already locked by another instance
            Lock();
            throw;  // Re-throw to preserve stack trace
        }
        
        _dbManager = new DbManager(_vaultPath);
        
        try
        {
            await _dbManager.OpenAsync();
            
            // Load vault metadata
            var metadata = await _dbManager.LoadMetadataAsync();
            if (metadata == null)
            {
                throw new InvalidOperationException("Vault metadata not found");
            }
            
            // SECURITY: Verify master password using constant-time comparison
            if (!_keyDerivation.VerifyMasterPassword(masterPassword, metadata.Salt, metadata.VerificationHash))
            {
                // SECURITY: Don't reveal why authentication failed
                Lock();
                return false;
            }
            
            // SECURITY: Derive encryption key
            _encryptionKey = _keyDerivation.DeriveKey(masterPassword, metadata.Salt);
            _encryption = new AesGcmEncryption(_encryptionKey);
            
            // Phase 6: Load MFA settings if enabled
            if (!string.IsNullOrEmpty(metadata.MfaSettingsJson))
            {
                _mfaSettings = MfaSettings.FromJson(metadata.MfaSettingsJson);
                if (_mfaSettings != null && _mfaSettings.Enabled)
                {
                    _mfaVerificationService = new MfaVerificationService(_vaultPath, _mfaSettings);

                    if (mfaVerifier != null)
                    {
                        var mfaOk = await mfaVerifier(_mfaVerificationService);
                        if (!mfaOk)
                        {
                            Lock();
                            return false;
                        }
                    }
                }
            }
            
            // Update last accessed timestamp
            await _dbManager.UpdateLastAccessedAsync();
            
            return true;
        }
        catch
        {
            Lock();
            throw;
        }
    }
    
    /// <summary>
    /// Lock the vault and clear sensitive data from memory.
    /// 
    /// SECURITY:
    /// - Clears encryption key from memory
    /// - Disposes encryption instance
    /// - Closes database connection
    /// </summary>
    public void Lock()
    {
        // SECURITY: Clear encryption key from memory
        if (_encryptionKey != null)
        {
            CryptographicOperations.ZeroMemory(_encryptionKey);
            _encryptionKey = null;
        }
        
        // SECURITY: Dispose encryption (clears key)
        _encryption?.Dispose();
        _encryption = null;
        
        // Dispose key derivation
        _keyDerivation?.Dispose();
        _keyDerivation = null;
        
        // Close database connection
        _dbManager?.Dispose();
        _dbManager = null;
        
        // Phase 4: Release exclusive file lock
        if (_vaultFileLock != null)
        {
            try
            {
                _vaultFileLock.Dispose();
                // Delete the lock file
                string lockFilePath = _vaultPath + ".lock";
                if (File.Exists(lockFilePath))
                {
                    File.Delete(lockFilePath);
                }
            }
            catch
            {
                // Ignore errors during lock cleanup
            }
            _vaultFileLock = null;
        }
        
        // Phase 6: Clear MFA state
        _mfaSettings = null;
        _mfaVerificationService = null;
        
        // Raise event
        VaultLocked?.Invoke(this, EventArgs.Empty);
    }
    
    /// <summary>
    /// Add a new password entry.
    /// 
    /// SECURITY:
    /// - Validates all input fields
    /// - Encrypts all sensitive data before storage
    /// </summary>
    public async Task<long> AddEntryAsync(PasswordEntry entry)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        ArgumentNullException.ThrowIfNull(entry);
        
        // SECURITY: Validate all fields
        var errors = Validators.ValidateEntry(
            entry.ServiceName,
            entry.Username,
            entry.Password,
            entry.Url,
            entry.Notes,
            entry.Category);
        
        if (errors.Count > 0)
        {
            throw new ArgumentException(
                string.Join("; ", errors.Select(e => e.ErrorMessage)));
        }
        
        // SECURITY: Encrypt all sensitive fields
        var encryptedEntry = EncryptEntry(entry);
        
        try
        {
            return await _dbManager!.InsertEntryAsync(encryptedEntry);
        }
        finally
        {
            // SECURITY: Clear encrypted entry from memory
            encryptedEntry.SecureClear();
        }
    }
    
    /// <summary>
    /// Update an existing password entry.
    /// 
    /// SECURITY:
    /// - Validates all input fields
    /// - Encrypts all sensitive data before storage
    /// </summary>
    public async Task UpdateEntryAsync(PasswordEntry entry)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        ArgumentNullException.ThrowIfNull(entry);
        
        if (entry.Id <= 0)
        {
            throw new ArgumentException("Entry ID must be positive", nameof(entry));
        }
        
        // SECURITY: Validate all fields
        var errors = Validators.ValidateEntry(
            entry.ServiceName,
            entry.Username,
            entry.Password,
            entry.Url,
            entry.Notes,
            entry.Category);
        
        if (errors.Count > 0)
        {
            throw new ArgumentException(
                string.Join("; ", errors.Select(e => e.ErrorMessage)));
        }
        
        // Update modification timestamp
        entry.ModifiedAt = DateTime.UtcNow;
        
        // SECURITY: Encrypt all sensitive fields
        var encryptedEntry = EncryptEntry(entry);
        
        try
        {
            await _dbManager!.UpdateEntryAsync(encryptedEntry);
        }
        finally
        {
            encryptedEntry.SecureClear();
        }
    }
    
    /// <summary>
    /// Delete a password entry.
    /// </summary>
    public async Task DeleteEntryAsync(long id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        if (id <= 0)
        {
            throw new ArgumentException("Entry ID must be positive", nameof(id));
        }
        
        await _dbManager!.DeleteEntryAsync(id);
    }
    
    /// <summary>
    /// Get a decrypted password entry by ID.
    /// 
    /// SECURITY:
    /// - Decrypts all fields
    /// - Caller is responsible for disposing the entry
    /// </summary>
    public async Task<PasswordEntry?> GetEntryAsync(long id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        if (id <= 0)
        {
            throw new ArgumentException("Entry ID must be positive", nameof(id));
        }
        
        var encryptedEntry = await _dbManager!.GetEntryByIdAsync(id);
        if (encryptedEntry == null)
        {
            return null;
        }
        
        try
        {
            return DecryptEntry(encryptedEntry);
        }
        finally
        {
            encryptedEntry.SecureClear();
        }
    }
    
    /// <summary>
    /// Get all decrypted password entries.
    /// 
    /// SECURITY:
    /// - Decrypts all entries
    /// - Caller is responsible for disposing entries
    /// </summary>
    public async Task<List<PasswordEntry>> GetAllEntriesAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        var encryptedEntries = await _dbManager!.GetAllEntriesAsync();
        var entries = new List<PasswordEntry>(encryptedEntries.Count);
        
        foreach (var encrypted in encryptedEntries)
        {
            try
            {
                entries.Add(DecryptEntry(encrypted));
            }
            finally
            {
                encrypted.SecureClear();
            }
        }
        
        return entries;
    }
    
    /// <summary>
    /// Get favorite entries only.
    /// </summary>
    public async Task<List<PasswordEntry>> GetFavoriteEntriesAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        var encryptedEntries = await _dbManager!.GetFavoriteEntriesAsync();
        var entries = new List<PasswordEntry>(encryptedEntries.Count);
        
        foreach (var encrypted in encryptedEntries)
        {
            try
            {
                entries.Add(DecryptEntry(encrypted));
            }
            finally
            {
                encrypted.SecureClear();
            }
        }
        
        return entries;
    }
    
    /// <summary>
    /// Get total entry count.
    /// </summary>
    public async Task<int> GetEntryCountAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        return await _dbManager!.GetEntryCountAsync();
    }
    
    /// <summary>
    /// Change the master password.
    /// 
    /// SECURITY:
    /// - Re-encrypts all entries with new key
    /// - Uses transaction for atomicity
    /// </summary>
    public async Task ChangeMasterPasswordAsync(string currentPassword, string newPassword)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        // SECURITY: Validate new password
        var validation = Validators.ValidateMasterPassword(newPassword);
        if (!validation.IsValid)
        {
            throw new ArgumentException(validation.ErrorMessage, nameof(newPassword));
        }
        
        // SECURITY: Verify current password first
        var metadata = await _dbManager!.LoadMetadataAsync();
        if (metadata == null || !_keyDerivation!.VerifyMasterPassword(currentPassword, metadata.Salt, metadata.VerificationHash))
        {
            throw new UnauthorizedAccessException("Current password is incorrect");
        }
        
        // Generate new salt and derive new key
        var newSalt = KeyDerivation.GenerateSalt();
        var newKey = _keyDerivation.DeriveKey(newPassword, newSalt);
        var newVerificationHash = _keyDerivation.CreateVerificationHash(newPassword, newSalt);
        
        try
        {
            // Get all entries decrypted with current key
            var entries = await GetAllEntriesAsync();
            
            // Create new encryption with new key
            using var newEncryption = new AesGcmEncryption(newKey);
            
            // Re-encrypt all entries with new key in a transaction
            await _dbManager.ExecuteInTransactionAsync(async () =>
            {
                // Update metadata with new salt and verification hash
                var newMetadata = new VaultMetadata
                {
                    Salt = newSalt,
                    VerificationHash = newVerificationHash,
                    CreatedAt = metadata.CreatedAt,
                    LastAccessedAt = DateTime.UtcNow,
                    SchemaVersion = metadata.SchemaVersion,
                    MfaSettingsJson = metadata.MfaSettingsJson
                };
                await _dbManager.SaveMetadataAsync(newMetadata);
                
                // Re-encrypt each entry
                foreach (var entry in entries)
                {
                    var encrypted = EncryptEntryWithKey(entry, newEncryption);
                    try
                    {
                        await _dbManager.UpdateEntryAsync(encrypted);
                    }
                    finally
                    {
                        encrypted.SecureClear();
                    }
                }
            });
            
            // Update current encryption key
            CryptographicOperations.ZeroMemory(_encryptionKey!);
            _encryptionKey = newKey;
            _encryption?.Dispose();
            _encryption = new AesGcmEncryption(_encryptionKey);
            
            // Dispose entries
            foreach (var entry in entries)
            {
                entry.Dispose();
            }
        }
        catch
        {
            // SECURITY: Clear new key on failure
            CryptographicOperations.ZeroMemory(newKey);
            throw;
        }
    }
    
    private EncryptedPasswordEntry EncryptEntry(PasswordEntry entry)
    {
        return EncryptEntryWithKey(entry, _encryption!);
    }
    
    private static EncryptedPasswordEntry EncryptEntryWithKey(PasswordEntry entry, AesGcmEncryption encryption)
    {
        // SECURITY: Create field-specific encrypted fields with AAD
        using var serviceField = new EncryptedField(encryption, "service_name");
        using var usernameField = new EncryptedField(encryption, "username");
        using var passwordField = new EncryptedField(encryption, "password");
        using var urlField = new EncryptedField(encryption, "url");
        using var notesField = new EncryptedField(encryption, "notes");
        using var categoryField = new EncryptedField(encryption, "category");
        
        return new EncryptedPasswordEntry
        {
            Id = entry.Id,
            EncryptedServiceName = serviceField.Encrypt(entry.ServiceName),
            EncryptedUsername = usernameField.Encrypt(entry.Username),
            EncryptedPassword = passwordField.Encrypt(entry.Password),
            EncryptedUrl = string.IsNullOrEmpty(entry.Url) ? null : urlField.Encrypt(entry.Url),
            EncryptedNotes = string.IsNullOrEmpty(entry.Notes) ? null : notesField.Encrypt(entry.Notes),
            EncryptedCategory = string.IsNullOrEmpty(entry.Category) ? null : categoryField.Encrypt(entry.Category),
            CreatedAt = entry.CreatedAt,
            ModifiedAt = entry.ModifiedAt,
            PasswordChangedAt = entry.PasswordChangedAt,
            IsFavorite = entry.IsFavorite
        };
    }
    
    private PasswordEntry DecryptEntry(EncryptedPasswordEntry encrypted)
    {
        // SECURITY: Create field-specific encrypted fields with AAD
        using var serviceField = new EncryptedField(_encryption!, "service_name");
        using var usernameField = new EncryptedField(_encryption!, "username");
        using var passwordField = new EncryptedField(_encryption!, "password");
        using var urlField = new EncryptedField(_encryption!, "url");
        using var notesField = new EncryptedField(_encryption!, "notes");
        using var categoryField = new EncryptedField(_encryption!, "category");
        
        return new PasswordEntry
        {
            Id = encrypted.Id,
            ServiceName = serviceField.Decrypt(encrypted.EncryptedServiceName),
            Username = usernameField.Decrypt(encrypted.EncryptedUsername),
            Password = passwordField.Decrypt(encrypted.EncryptedPassword),
            Url = encrypted.EncryptedUrl != null ? urlField.Decrypt(encrypted.EncryptedUrl) : null,
            Notes = encrypted.EncryptedNotes != null ? notesField.Decrypt(encrypted.EncryptedNotes) : null,
            Category = encrypted.EncryptedCategory != null ? categoryField.Decrypt(encrypted.EncryptedCategory) : null,
            CreatedAt = encrypted.CreatedAt,
            ModifiedAt = encrypted.ModifiedAt,
            PasswordChangedAt = encrypted.PasswordChangedAt,
            IsFavorite = encrypted.IsFavorite
        };
    }
    
    private void EnsureUnlocked()
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("Vault is locked. Call UnlockVaultAsync() first.");
        }
    }
    
    /// <summary>
    /// Get current MFA settings for this vault.
    /// </summary>
    /// <returns>MfaSettings if MFA is enabled, null otherwise</returns>
    public MfaSettings? GetMfaSettings()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _mfaSettings;
    }
    
    /// <summary>
    /// Enable MFA for this vault.
    /// Generates TOTP secret and recovery codes, stores encrypted in vault metadata.
    /// </summary>
    /// <param name="totpSecretBase32">Base32-encoded TOTP secret (from QR code)</param>
    /// <param name="recoveryCodes">List of plaintext recovery codes to hash and store</param>
    public async Task EnableMfaAsync(string totpSecretBase32, List<string> recoveryCodes)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        if (string.IsNullOrEmpty(totpSecretBase32))
            throw new ArgumentException("TOTP secret cannot be empty", nameof(totpSecretBase32));
        
        if (recoveryCodes == null || recoveryCodes.Count == 0)
            throw new ArgumentException("Recovery codes cannot be empty", nameof(recoveryCodes));
        
        if (_encryption == null)
            throw new InvalidOperationException("Vault must be unlocked");
        
        // Create MFA settings
        var mfaSettings = new MfaSettings
        {
            Enabled = true,
            Method = "totp",
            CreatedAt = DateTime.UtcNow
        };
        
        // Encrypt TOTP secret with vault's encryption key
        byte[] totpSecretBytes = System.Text.Encoding.UTF8.GetBytes(totpSecretBase32);
        byte[] encryptedTotpSecret = _encryption.Encrypt(totpSecretBytes);
        mfaSettings.EncryptedTotpSecretHex = Convert.ToHexString(encryptedTotpSecret);
        
        // Hash and store recovery codes
        foreach (var code in recoveryCodes)
        {
            var salt = KeyDerivation.GenerateSalt();
            var codeHash = MfaProvider.HashRecoveryCode(code, salt);
            mfaSettings.RecoveryCodeHashesHex.Add($"{Convert.ToHexString(salt)}:{Convert.ToHexString(codeHash)}");
        }
        
        // Save MFA settings to vault metadata
        _mfaSettings = mfaSettings;
        var metadata = await _dbManager!.LoadMetadataAsync();
        if (metadata != null)
        {
            metadata.MfaSettingsJson = mfaSettings.ToJson();
            await _dbManager.SaveMetadataAsync(metadata);
        }

        _mfaVerificationService = new MfaVerificationService(_vaultPath, mfaSettings);
    }
    
    /// <summary>
    /// Disable MFA for this vault.
    /// </summary>
    public async Task DisableMfaAsync()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();
        
        _mfaSettings = null;
        _mfaVerificationService = null;
        
        var metadata = await _dbManager!.LoadMetadataAsync();
        if (metadata != null)
        {
            metadata.MfaSettingsJson = null;
            await _dbManager.SaveMetadataAsync(metadata);
        }
    }
    
    /// <summary>
    /// Get MFA verification service for this vault.
    /// Returns null if MFA is not enabled.
    /// </summary>
    public MfaVerificationService? GetMfaVerificationService()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        if (_mfaSettings == null || !_mfaSettings.Enabled)
            return null;
        
        _mfaVerificationService ??= new MfaVerificationService(_vaultPath, _mfaSettings);
        return _mfaVerificationService;
    }

    /// <summary>
    /// Verify TOTP code against vault MFA settings.
    /// </summary>
    public bool VerifyMfaTotpCode(string totpCode)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();

        if (_mfaSettings == null || !_mfaSettings.Enabled)
            return true;

        if (_encryption == null || _mfaVerificationService == null)
            throw new InvalidOperationException("MFA is not initialized for this vault.");

        if (string.IsNullOrEmpty(_mfaSettings.EncryptedTotpSecretHex))
            throw new InvalidOperationException("MFA secret is missing.");

        var encryptedSecret = Convert.FromHexString(_mfaSettings.EncryptedTotpSecretHex);
        byte[] secretBytes = _encryption.Decrypt(encryptedSecret);

        try
        {
            var secretBase32 = System.Text.Encoding.UTF8.GetString(secretBytes);
            var verified = _mfaVerificationService.VerifyTotpCode(totpCode, secretBase32);
            if (verified)
            {
                _mfaSettings.VerifiedAt = DateTime.UtcNow;
            }

            return verified;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    /// <summary>
    /// Verify and consume a recovery code.
    /// </summary>
    public async Task<bool> VerifyRecoveryCodeAsync(string recoveryCode)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        EnsureUnlocked();

        if (_mfaSettings == null || !_mfaSettings.Enabled)
            return true;

        if (_mfaVerificationService == null)
            throw new InvalidOperationException("MFA is not initialized for this vault.");

        var result = _mfaVerificationService.VerifyRecoveryCode(recoveryCode, _mfaSettings.RecoveryCodeHashesHex);
        if (!result.isValid)
            return false;

        _mfaSettings.VerifiedAt = DateTime.UtcNow;
        var metadata = await _dbManager!.LoadMetadataAsync();
        if (metadata != null)
        {
            metadata.MfaSettingsJson = _mfaSettings.ToJson();
            await _dbManager.SaveMetadataAsync(metadata);
        }

        return true;
    }
    
    /// <summary>
    /// Dispose vault service and clean up sensitive data.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            Lock();
            
            // SECURITY: Properly dispose database manager to release file lock
            _dbManager?.Dispose();
            _dbManager = null;
            
            _disposed = true;
        }
    }
}
