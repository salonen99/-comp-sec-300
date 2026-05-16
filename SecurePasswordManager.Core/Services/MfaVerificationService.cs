/*
 * MFA Verification Service
 * 
 * SECURITY FEATURES:
 * - Rate limiting: 5 failed MFA attempts → 5-minute lockout per vault
 * - TOTP verification with constant-time comparison (CWE-697)
 * - Recovery code verification with constant-time hashing (CWE-697)
 * - Session-based MFA state tracking
 * - Thread-safe rate limiting using locks
 */

using System.Security.Cryptography;
using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Models;

namespace SecurePasswordManager.Core.Services;

/// <summary>
/// Service for verifying MFA credentials (TOTP codes and recovery codes).
/// 
/// SECURITY NOTES:
/// - Rate limits MFA attempts to prevent brute-force attacks
/// - Uses Argon2id for constant-time recovery code comparison
/// - Tracks failed attempts per vault with automatic lockout
/// - Session-based MFA verification tracking
/// </summary>
public class MfaVerificationService
{
    // SECURITY: Rate limiting constants
    private const int MaxFailedAttempts = 5;
    private const int LockoutDurationMinutes = 5;
    
    // Rate limiting state per vault (vault file path → attempt tracking)
    private static readonly Dictionary<string, MfaRateLimitEntry> RateLimitStates = new();
    private static readonly object RateLimitLock = new object();
    
    private readonly string _vaultFilePath;
    private readonly MfaSettings _mfaSettings;
    private DateTime? _mfaVerifiedAt;
    
    /// <summary>
    /// Initialize MFA verification service for a vault.
    /// </summary>
    /// <param name="vaultFilePath">Path to vault file (for rate limiting tracking)</param>
    /// <param name="mfaSettings">Vault's MFA settings</param>
    public MfaVerificationService(string vaultFilePath, MfaSettings mfaSettings)
    {
        _vaultFilePath = vaultFilePath ?? throw new ArgumentNullException(nameof(vaultFilePath));
        _mfaSettings = mfaSettings ?? throw new ArgumentNullException(nameof(mfaSettings));
    }
    
    /// <summary>
    /// Verify a TOTP code from authenticator app.
    /// 
    /// SECURITY:
    /// - Checks rate limiting before verification
    /// - Uses OtpNet library for RFC 6238 compliance
    /// - Updates rate limit state on failure
    /// - Verifies against decrypted TOTP secret
    /// </summary>
    /// <param name="totpCode">6-digit code from authenticator</param>
    /// <param name="totpSecretBase32">Decrypted TOTP secret as Base32 text</param>
    /// <returns>True if code is valid, false if invalid or rate-limited</returns>
    /// <exception cref="InvalidOperationException">If rate-limited (includes lockout duration)</exception>
    public bool VerifyTotpCode(string totpCode, string totpSecretBase32)
    {
        if (string.IsNullOrEmpty(totpCode))
            throw new ArgumentException("TOTP code cannot be empty", nameof(totpCode));
        
        if (string.IsNullOrEmpty(totpSecretBase32))
            throw new ArgumentException("TOTP secret cannot be empty", nameof(totpSecretBase32));
        
        // SECURITY: Check rate limiting before attempting verification
        var rateLimitStatus = GetRateLimitStatus();
        if (rateLimitStatus.IsLockedOut)
        {
            throw new InvalidOperationException(
                $"MFA verification locked out. Please try again in {rateLimitStatus.RemainingLockoutSeconds} seconds.");
        }
        
        // SECURITY: Verify TOTP code
        bool isValid = MfaProvider.VerifyTotpCode(totpSecretBase32, totpCode);
        
        if (!isValid)
        {
            // SECURITY: Record failed attempt
            lock (RateLimitLock)
            {
                if (!RateLimitStates.TryGetValue(_vaultFilePath, out var entry))
                {
                    entry = new MfaRateLimitEntry();
                    RateLimitStates[_vaultFilePath] = entry;
                }
                
                entry.FailedAttempts++;
                entry.LastAttemptAt = DateTime.UtcNow;
            }
            
            return false;
        }
        
        // SECURITY: Clear rate limit on successful verification
        lock (RateLimitLock)
        {
            if (RateLimitStates.ContainsKey(_vaultFilePath))
            {
                RateLimitStates.Remove(_vaultFilePath);
            }
        }
        
        // Record MFA verification timestamp
        _mfaVerifiedAt = DateTime.UtcNow;
        
        return true;
    }
    
    /// <summary>
    /// Verify a recovery code (backup code).
    /// 
    /// SECURITY:
    /// - Checks rate limiting before verification
    /// - Constant-time comparison using Argon2id hashing
    /// - Marks recovery code as used after successful verification
    /// - Prevents reuse of recovery codes
    /// </summary>
    /// <param name="recoveryCode">8-character recovery code</param>
    /// <param name="recoveryCodeHashesHex">List of hex-encoded recovery code hashes from MfaSettings</param>
    /// <returns>Tuple: (isValid, codeIndex) where codeIndex is position if valid, -1 otherwise</returns>
    /// <exception cref="InvalidOperationException">If rate-limited</exception>
    public (bool isValid, int codeIndex) VerifyRecoveryCode(string recoveryCode, List<string> recoveryCodeHashesHex)
    {
        if (string.IsNullOrEmpty(recoveryCode))
            throw new ArgumentException("Recovery code cannot be empty", nameof(recoveryCode));
        
        if (recoveryCodeHashesHex == null || recoveryCodeHashesHex.Count == 0)
            throw new ArgumentException("Recovery code hashes cannot be empty", nameof(recoveryCodeHashesHex));
        
        // SECURITY: Check rate limiting before attempting verification
        var rateLimitStatus = GetRateLimitStatus();
        if (rateLimitStatus.IsLockedOut)
        {
            throw new InvalidOperationException(
                $"MFA verification locked out. Please try again in {rateLimitStatus.RemainingLockoutSeconds} seconds.");
        }
        
        // SECURITY: Try to verify against each recovery code hash
        int matchedIndex = -1;
        
        for (int i = 0; i < recoveryCodeHashesHex.Count; i++)
        {
            // SECURITY: Skip already-used codes
            if (_mfaSettings.IsRecoveryCodeUsed(i))
                continue;
            
            try
            {
                // Format: "saltHex:hashHex"
                var parts = recoveryCodeHashesHex[i].Split(':', 2);
                if (parts.Length != 2)
                    continue;

                byte[] salt = Convert.FromHexString(parts[0]);
                byte[] storedHash = Convert.FromHexString(parts[1]);
                byte[] inputHash = MfaProvider.HashRecoveryCode(recoveryCode, salt);
                
                // SECURITY (CWE-697): Constant-time comparison
                if (CryptographicOperations.FixedTimeEquals(storedHash, inputHash))
                {
                    matchedIndex = i;
                    break;
                }
            }
            catch (FormatException)
            {
                // Invalid hex format - skip this hash
                continue;
            }
        }
        
        if (matchedIndex == -1)
        {
            // SECURITY: Record failed attempt
            lock (RateLimitLock)
            {
                if (!RateLimitStates.TryGetValue(_vaultFilePath, out var entry))
                {
                    entry = new MfaRateLimitEntry();
                    RateLimitStates[_vaultFilePath] = entry;
                }
                
                entry.FailedAttempts++;
                entry.LastAttemptAt = DateTime.UtcNow;
            }
            
            return (false, -1);
        }
        
        // SECURITY: Mark recovery code as used
        _mfaSettings.MarkRecoveryCodeAsUsed(matchedIndex);
        
        // SECURITY: Clear rate limit on successful verification
        lock (RateLimitLock)
        {
            if (RateLimitStates.ContainsKey(_vaultFilePath))
            {
                RateLimitStates.Remove(_vaultFilePath);
            }
        }
        
        // Record MFA verification timestamp
        _mfaVerifiedAt = DateTime.UtcNow;
        
        return (true, matchedIndex);
    }
    
    /// <summary>
    /// Get current rate limit status for this vault's MFA attempts.
    /// </summary>
    /// <returns>Rate limit info including lockout status and duration</returns>
    public MfaRateLimitStatus GetRateLimitStatus()
    {
        lock (RateLimitLock)
        {
            if (!RateLimitStates.TryGetValue(_vaultFilePath, out var entry))
            {
                return new MfaRateLimitStatus
                {
                    IsLockedOut = false,
                    RemainingLockoutSeconds = 0,
                    FailedAttempts = 0,
                    RemainingAttempts = MaxFailedAttempts
                };
            }
            
            // Check if lockout period has expired
            var timeSinceLastAttempt = DateTime.UtcNow - entry.LastAttemptAt;
            if (timeSinceLastAttempt.TotalMinutes >= LockoutDurationMinutes)
            {
                // Lockout expired, reset counter
                RateLimitStates.Remove(_vaultFilePath);
                return new MfaRateLimitStatus
                {
                    IsLockedOut = false,
                    RemainingLockoutSeconds = 0,
                    FailedAttempts = 0,
                    RemainingAttempts = MaxFailedAttempts
                };
            }
            
            bool isLockedOut = entry.FailedAttempts >= MaxFailedAttempts;
            int remainingSeconds = (int)(LockoutDurationMinutes * 60 - timeSinceLastAttempt.TotalSeconds);
            
            return new MfaRateLimitStatus
            {
                IsLockedOut = isLockedOut,
                RemainingLockoutSeconds = remainingSeconds,
                FailedAttempts = entry.FailedAttempts,
                RemainingAttempts = Math.Max(0, MaxFailedAttempts - entry.FailedAttempts)
            };
        }
    }
    
    /// <summary>
    /// Check if MFA has been verified in this session.
    /// </summary>
    public bool IsMfaVerified()
    {
        return _mfaVerifiedAt.HasValue && _mfaVerifiedAt > DateTime.UtcNow.AddHours(-24);
    }
    
    /// <summary>
    /// Get timestamp of last MFA verification.
    /// </summary>
    public DateTime? GetLastMfaVerificationTime()
    {
        return _mfaVerifiedAt;
    }
    
    /// <summary>
    /// Clear MFA verification state (for session timeout/restart).
    /// </summary>
    public void ClearMfaVerificationState()
    {
        _mfaVerifiedAt = null;
    }
    
    /// <summary>
    /// Internal class for tracking rate limit state per vault.
    /// </summary>
    private class MfaRateLimitEntry
    {
        public int FailedAttempts { get; set; }
        public DateTime LastAttemptAt { get; set; } = DateTime.UtcNow;
    }
}

/// <summary>
/// Rate limit status information for MFA verification.
/// </summary>
public class MfaRateLimitStatus
{
    /// <summary>
    /// Whether MFA verification is currently locked out due to too many failed attempts.
    /// </summary>
    public bool IsLockedOut { get; set; }
    
    /// <summary>
    /// Seconds remaining until lockout expires (0 if not locked out).
    /// </summary>
    public int RemainingLockoutSeconds { get; set; }
    
    /// <summary>
    /// Number of failed attempts so far in this lockout period.
    /// </summary>
    public int FailedAttempts { get; set; }
    
    /// <summary>
    /// Number of attempts remaining before lockout (0 if already locked out).
    /// </summary>
    public int RemainingAttempts { get; set; }
}
