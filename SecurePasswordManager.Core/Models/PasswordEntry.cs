/*
 * Password Entry Model
 * 
 * SECURITY FEATURES:
 * - All sensitive fields are stored encrypted in database
 * - Clear separation between encrypted and plaintext properties
 * - IDisposable for secure cleanup of sensitive data
 */

using System.Security.Cryptography;

namespace SecurePasswordManager.Core.Models;

/// <summary>
/// Represents a password entry in the vault.
/// 
/// SECURITY NOTES:
/// - Password, Username, and Notes are encrypted at rest
/// - ServiceName is also encrypted to prevent metadata leakage
/// - Use Dispose() to clear sensitive data from memory
/// </summary>
public sealed class PasswordEntry : IDisposable
{
    private bool _disposed;
    
    /// <summary>
    /// Unique identifier for the entry.
    /// </summary>
    public long Id { get; set; }
    
    /// <summary>
    /// Service/website name (plaintext, for display).
    /// </summary>
    public string ServiceName { get; set; } = string.Empty;
    
    /// <summary>
    /// Username or email (plaintext, for display).
    /// </summary>
    public string Username { get; set; } = string.Empty;
    
    /// <summary>
    /// Password (plaintext, sensitive - clear after use).
    /// </summary>
    public string Password { get; set; } = string.Empty;
    
    /// <summary>
    /// Optional URL for the service.
    /// </summary>
    public string? Url { get; set; }
    
    /// <summary>
    /// Optional notes (plaintext, for display).
    /// </summary>
    public string? Notes { get; set; }
    
    /// <summary>
    /// When the entry was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// When the entry was last modified.
    /// </summary>
    public DateTime ModifiedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// When the password was last changed.
    /// </summary>
    public DateTime? PasswordChangedAt { get; set; }
    
    /// <summary>
    /// Category/folder for organization.
    /// </summary>
    public string? Category { get; set; }
    
    /// <summary>
    /// Whether this entry is marked as favorite.
    /// </summary>
    public bool IsFavorite { get; set; }
    
    /// <summary>
    /// Securely clear sensitive data from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            // SECURITY: Clear sensitive strings
            // Note: C# strings are immutable, but we can at least
            // remove references and suggest garbage collection
            Password = string.Empty;
            ServiceName = string.Empty;
            Username = string.Empty;
            Notes = null;
            Url = null;
            
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}

/// <summary>
/// Encrypted version of PasswordEntry for database storage.
/// 
/// SECURITY:
/// All sensitive fields are stored as encrypted byte arrays.
/// </summary>
public sealed class EncryptedPasswordEntry
{
    public long Id { get; set; }
    
    /// <summary>
    /// Encrypted service name.
    /// </summary>
    public byte[] EncryptedServiceName { get; set; } = [];
    
    /// <summary>
    /// Encrypted username.
    /// </summary>
    public byte[] EncryptedUsername { get; set; } = [];
    
    /// <summary>
    /// Encrypted password.
    /// </summary>
    public byte[] EncryptedPassword { get; set; } = [];
    
    /// <summary>
    /// Encrypted URL (nullable).
    /// </summary>
    public byte[]? EncryptedUrl { get; set; }
    
    /// <summary>
    /// Encrypted notes (nullable).
    /// </summary>
    public byte[]? EncryptedNotes { get; set; }
    
    /// <summary>
    /// Encrypted category (nullable).
    /// </summary>
    public byte[]? EncryptedCategory { get; set; }
    
    public DateTime CreatedAt { get; set; }
    public DateTime ModifiedAt { get; set; }
    public DateTime? PasswordChangedAt { get; set; }
    public bool IsFavorite { get; set; }
    
    /// <summary>
    /// Securely clear encrypted data from memory.
    /// </summary>
    public void SecureClear()
    {
        CryptographicOperations.ZeroMemory(EncryptedServiceName);
        CryptographicOperations.ZeroMemory(EncryptedUsername);
        CryptographicOperations.ZeroMemory(EncryptedPassword);
        
        if (EncryptedUrl != null)
            CryptographicOperations.ZeroMemory(EncryptedUrl);
        if (EncryptedNotes != null)
            CryptographicOperations.ZeroMemory(EncryptedNotes);
        if (EncryptedCategory != null)
            CryptographicOperations.ZeroMemory(EncryptedCategory);
    }
}

/// <summary>
/// Vault metadata stored in the database.
/// </summary>
public sealed class VaultMetadata
{
    /// <summary>
    /// Salt used for key derivation.
    /// </summary>
    public byte[] Salt { get; set; } = [];
    
    /// <summary>
    /// Verification hash to confirm correct master password.
    /// </summary>
    public byte[] VerificationHash { get; set; } = [];
    
    /// <summary>
    /// When the vault was created.
    /// </summary>
    public DateTime CreatedAt { get; set; }
    
    /// <summary>
    /// When the vault was last accessed.
    /// </summary>
    public DateTime LastAccessedAt { get; set; }
    
    /// <summary>
    /// Schema version for migrations.
    /// </summary>
    public int SchemaVersion { get; set; } = 1;
    
    /// <summary>
    /// MFA settings as JSON string (null if MFA not enabled).
    /// </summary>
    public string? MfaSettingsJson { get; set; }
}
