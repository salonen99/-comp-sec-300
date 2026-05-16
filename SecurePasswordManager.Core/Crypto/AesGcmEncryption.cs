/*
 * AES-256-GCM Authenticated Encryption Module
 * 
 * SECURITY FEATURES (OWASP/SANS Compliance):
 * - CWE-327: Uses AES-256-GCM (strong, modern algorithm)
 * - CWE-329: Unique nonce/IV for every encryption operation
 * - CWE-353: Built-in authentication tag prevents tampering
 * - CWE-311: Data encrypted at rest
 * 
 * Why AES-256-GCM?
 * - AES: Advanced Encryption Standard (NIST approved)
 * - 256-bit key: Maximum security level
 * - GCM: Galois/Counter Mode provides:
 *   - Confidentiality (encryption)
 *   - Integrity (detects tampering)
 *   - Authentication (verifies source)
 * 
 * Nonce/IV Requirements:
 * - 12 bytes (96 bits) - Recommended for GCM
 * - Must be unique for each encryption with same key
 * - Using RandomNumberGenerator for cryptographic randomness
 */

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SecurePasswordManager.Core.Crypto;

/// <summary>
/// AES-256-GCM Authenticated Encryption.
/// 
/// SECURITY NOTES:
/// - Uses unique 12-byte nonce for each encryption
/// - Includes 16-byte authentication tag to detect tampering
/// - Supports associated data (AAD) for additional context
/// - Implements IDisposable for secure key clearing
/// </summary>
public sealed class AesGcmEncryption : IDisposable
{
    // SECURITY: Constants for cryptographic operations
    public const int KeySize = 32;          // 256 bits
    public const int NonceSize = 12;        // 96 bits (GCM recommended)
    public const int TagSize = 16;          // 128 bits authentication tag
    
    // SECURITY: Version byte for future algorithm upgrades
    private const byte CurrentVersion = 1;
    
    private readonly byte[] _key;
    private bool _disposed;
    
    /// <summary>
    /// Initialize encryption with a 256-bit key.
    /// </summary>
    /// <param name="key">32-byte encryption key (from key derivation)</param>
    /// <exception cref="ArgumentException">If key is not 32 bytes</exception>
    public AesGcmEncryption(byte[] key)
    {
        // SECURITY (CWE-20): Validate key length
        if (key == null || key.Length != KeySize)
        {
            throw new ArgumentException(
                $"Key must be exactly {KeySize} bytes (256 bits)",
                nameof(key));
        }
        
        // SECURITY: Make a copy of the key to prevent external modification
        _key = new byte[KeySize];
        key.CopyTo(_key, 0);
    }
    
    /// <summary>
    /// Generate a cryptographically secure random nonce.
    /// 
    /// SECURITY (CWE-329, CWE-330):
    /// - Uses RandomNumberGenerator (OS CSPRNG)
    /// - 12 bytes = 96 bits (GCM specification)
    /// - Must be unique for every encryption with same key
    /// </summary>
    public static byte[] GenerateNonce()
    {
        // SECURITY: RandomNumberGenerator uses OS-provided CSPRNG
        return RandomNumberGenerator.GetBytes(NonceSize);
    }
    
    /// <summary>
    /// Encrypt data using AES-256-GCM.
    /// 
    /// SECURITY:
    /// - Generates unique nonce for each call
    /// - Includes authentication tag
    /// - Nonce is prepended to ciphertext for storage
    /// 
    /// Format: [version:1][nonce:12][ciphertext:N][tag:16]
    /// </summary>
    /// <param name="plaintext">Data to encrypt</param>
    /// <param name="associatedData">Optional additional authenticated data (AAD)</param>
    /// <returns>Encrypted data with nonce and tag</returns>
    public byte[] Encrypt(byte[] plaintext, byte[]? associatedData = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        // SECURITY (CWE-20): Input validation
        ArgumentNullException.ThrowIfNull(plaintext);
        
        // SECURITY: Generate unique nonce for this encryption
        // CRITICAL: Never reuse a nonce with the same key
        byte[] nonce = GenerateNonce();
        
        // Allocate output buffer
        // Format: [version:1][nonce:12][ciphertext:N][tag:16]
        byte[] result = new byte[1 + NonceSize + plaintext.Length + TagSize];
        
        // Write version byte
        result[0] = CurrentVersion;
        
        // Write nonce
        nonce.CopyTo(result.AsSpan(1, NonceSize));
        
        // Create spans for ciphertext and tag
        Span<byte> ciphertext = result.AsSpan(1 + NonceSize, plaintext.Length);
        Span<byte> tag = result.AsSpan(1 + NonceSize + plaintext.Length, TagSize);
        
        // SECURITY: Encrypt with authentication using AES-GCM
        using var aesGcm = new AesGcm(_key, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        
        return result;
    }
    
    /// <summary>
    /// Decrypt data using AES-256-GCM.
    /// 
    /// SECURITY:
    /// - Extracts nonce from ciphertext
    /// - Verifies authentication tag (detects tampering)
    /// - Throws exception if authentication fails
    /// </summary>
    /// <param name="ciphertext">Data from Encrypt() method</param>
    /// <param name="associatedData">Must match AAD used during encryption</param>
    /// <returns>Decrypted plaintext</returns>
    /// <exception cref="ArgumentException">If ciphertext format is invalid</exception>
    /// <exception cref="CryptographicException">If authentication fails (tampering detected)</exception>
    public byte[] Decrypt(byte[] ciphertext, byte[]? associatedData = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        
        // SECURITY (CWE-20): Input validation
        int minLength = 1 + NonceSize + TagSize; // version + nonce + tag (empty plaintext)
        if (ciphertext == null || ciphertext.Length < minLength)
        {
            throw new ArgumentException(
                $"Ciphertext too short (minimum {minLength} bytes)",
                nameof(ciphertext));
        }
        
        // SECURITY: Extract and validate version byte
        byte version = ciphertext[0];
        if (version != CurrentVersion)
        {
            throw new ArgumentException(
                $"Unsupported encryption version: {version}",
                nameof(ciphertext));
        }
        
        // Extract components
        ReadOnlySpan<byte> nonce = ciphertext.AsSpan(1, NonceSize);
        int encryptedLength = ciphertext.Length - 1 - NonceSize - TagSize;
        ReadOnlySpan<byte> encrypted = ciphertext.AsSpan(1 + NonceSize, encryptedLength);
        ReadOnlySpan<byte> tag = ciphertext.AsSpan(1 + NonceSize + encryptedLength, TagSize);
        
        // Allocate plaintext buffer
        byte[] plaintext = new byte[encryptedLength];
        
        try
        {
            // SECURITY: Decrypt and verify authentication tag
            // If tampering detected, CryptographicException is thrown
            using var aesGcm = new AesGcm(_key, TagSize);
            aesGcm.Decrypt(nonce, encrypted, tag, plaintext, associatedData);
            
            return plaintext;
        }
        catch (CryptographicException)
        {
            // SECURITY: Authentication failed - data was tampered with
            // or wrong key/AAD was used. Clear any partial plaintext.
            CryptographicOperations.ZeroMemory(plaintext);
            
            throw new CryptographicException(
                "Decryption failed: Authentication tag verification failed. " +
                "Data may have been tampered with or wrong key was used.");
        }
    }
    
    /// <summary>
    /// Convenience method to encrypt a string (UTF-8 encoded).
    /// </summary>
    public byte[] EncryptString(string plaintext, byte[]? associatedData = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Encrypt(Encoding.UTF8.GetBytes(plaintext), associatedData);
    }
    
    /// <summary>
    /// Convenience method to decrypt to a string.
    /// </summary>
    public string DecryptString(byte[] ciphertext, byte[]? associatedData = null)
    {
        byte[] plaintext = Decrypt(ciphertext, associatedData);
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            // SECURITY: Clear plaintext bytes after conversion
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
    
    /// <summary>
    /// Securely dispose resources and clear the key from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            // SECURITY: Guaranteed to clear key from memory
            CryptographicOperations.ZeroMemory(_key);
            _disposed = true;
        }
    }
}

/// <summary>
/// Helper class for encrypting individual database fields.
/// 
/// SECURITY:
/// Provides a consistent interface for field-level encryption
/// with field-specific AAD (Additional Authenticated Data).
/// </summary>
public sealed class EncryptedField : IDisposable
{
    private readonly AesGcmEncryption _encryption;
    private readonly byte[] _aad;
    private bool _disposed;
    
    /// <summary>
    /// Initialize encrypted field handler.
    /// </summary>
    /// <param name="encryption">AesGcmEncryption instance</param>
    /// <param name="fieldName">Name of the field (used as AAD)</param>
    public EncryptedField(AesGcmEncryption encryption, string fieldName)
    {
        _encryption = encryption ?? throw new ArgumentNullException(nameof(encryption));
        
        // SECURITY: Use field name as AAD to bind ciphertext to context
        // This prevents "cut and paste" attacks where encrypted values
        // are moved between fields
        _aad = Encoding.UTF8.GetBytes($"field:{fieldName}");
    }
    
    /// <summary>
    /// Encrypt a field value.
    /// </summary>
    public byte[] Encrypt(string value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _encryption.EncryptString(value, _aad);
    }
    
    /// <summary>
    /// Decrypt a field value.
    /// </summary>
    public string Decrypt(byte[] ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _encryption.DecryptString(ciphertext, _aad);
    }
    
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_aad);
            _disposed = true;
        }
    }
}
