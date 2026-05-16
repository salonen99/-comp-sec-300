/*
 * MFA Settings Model
 * 
 * SECURITY:
 * - Stores TOTP secret encrypted with vault's derived key (AES-256-GCM)
 * - Recovery codes stored as Argon2id hashes only (never plaintext)
 * - Tracks which recovery codes have been used
 * - Records when MFA was enabled and last verified
 */

using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecurePasswordManager.Core.Models;

/// <summary>
/// Multi-Factor Authentication settings for a vault.
/// 
/// SECURITY NOTES:
/// - Enabled, Method, and timestamps are stored plaintext in database
/// - EncryptedTotpSecret is encrypted with AES-256-GCM before storage
/// - RecoveryCodeHashes are stored as Argon2id hashes (one-way)
/// - This model is serialized to JSON for vault_metadata storage
/// </summary>
public class MfaSettings
{
    /// <summary>
    /// Whether MFA is enabled for this vault.
    /// </summary>
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }
    
    /// <summary>
    /// MFA method used ('totp' for Time-based One-Time Password).
    /// </summary>
    [JsonPropertyName("method")]
    public string Method { get; set; } = "totp";
    
    /// <summary>
    /// Encrypted TOTP secret (32-byte key encrypted with AES-256-GCM).
    /// Stored as hex string in JSON.
    /// </summary>
    [JsonPropertyName("encrypted_totp_secret")]
    public string? EncryptedTotpSecretHex { get; set; }
    
    /// <summary>
    /// List of recovery code hashes (Argon2id-hashed, stored as hex strings).
    /// Each hash represents a recovery code that can be used once.
    /// </summary>
    [JsonPropertyName("recovery_code_hashes")]
    public List<string> RecoveryCodeHashesHex { get; set; } = new();
    
    /// <summary>
    /// Bit vector tracking which recovery codes have been used.
    /// Each bit represents whether the corresponding recovery code was used.
    /// Example: If bit 3 is set, recovery code at index 3 was already used.
    /// </summary>
    [JsonPropertyName("recovery_codes_used")]
    public int RecoveryCodesUsedBitVector { get; set; }
    
    /// <summary>
    /// When MFA was enabled for this vault (ISO 8601 UTC).
    /// </summary>
    [JsonPropertyName("created_at")]
    public DateTime CreatedAt { get; set; }
    
    /// <summary>
    /// When MFA was last verified during this session (ISO 8601 UTC).
    /// Used to determine if MFA re-verification is needed.
    /// </summary>
    [JsonPropertyName("verified_at")]
    public DateTime? VerifiedAt { get; set; }
    
    /// <summary>
    /// Serialize MFA settings to JSON string for database storage.
    /// </summary>
    public string ToJson()
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = false });
    }
    
    /// <summary>
    /// Deserialize MFA settings from JSON string (from database storage).
    /// </summary>
    public static MfaSettings? FromJson(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<MfaSettings>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
    
    /// <summary>
    /// Mark a recovery code as used (by index).
    /// </summary>
    public void MarkRecoveryCodeAsUsed(int codeIndex)
    {
        if (codeIndex < 0 || codeIndex >= 32)
            throw new ArgumentOutOfRangeException(nameof(codeIndex), "Recovery code index must be 0-31");
        
        // Set bit at position codeIndex
        RecoveryCodesUsedBitVector |= (1 << codeIndex);
    }
    
    /// <summary>
    /// Check if a recovery code has already been used.
    /// </summary>
    public bool IsRecoveryCodeUsed(int codeIndex)
    {
        if (codeIndex < 0 || codeIndex >= 32)
            throw new ArgumentOutOfRangeException(nameof(codeIndex), "Recovery code index must be 0-31");
        
        // Check if bit at position codeIndex is set
        return (RecoveryCodesUsedBitVector & (1 << codeIndex)) != 0;
    }
    
    /// <summary>
    /// Get count of remaining unused recovery codes.
    /// </summary>
    public int GetRemainingRecoveryCodeCount()
    {
        int total = RecoveryCodeHashesHex.Count;
        int used = 0;
        
        for (int i = 0; i < total; i++)
        {
            if (IsRecoveryCodeUsed(i))
                used++;
        }
        
        return total - used;
    }
}
