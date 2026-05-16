/*
 * Multi-Factor Authentication (MFA) Provider Module
 * 
 * SECURITY FEATURES:
 * - RFC 6238 compliant TOTP (Time-based One-Time Password) generation
 * - 32-byte (256-bit) cryptographically secure TOTP secrets
 * - 6-digit TOTP codes with ±1 time step tolerance (30-second window)
 * - Recovery codes for backup access (10 codes, 8 characters each)
 * - Recovery codes hashed with Argon2id (never stored plaintext)
 * - Uses RandomNumberGenerator for cryptographic randomness (not System.Random)
 */

using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace SecurePasswordManager.Core.Crypto;

/// <summary>
/// Multi-Factor Authentication (MFA) provider with TOTP and recovery codes.
/// 
/// SECURITY NOTES:
/// - TOTP secret is 32 bytes (256 bits) of cryptographically secure random data
/// - TOTP implementation follows RFC 6238 (Time-based One-Time Password)
/// - Recovery codes are randomly generated, hashed with Argon2id, never stored plaintext
/// - TOTP verification accepts ±1 time step for clock skew tolerance
/// - All random generation uses RandomNumberGenerator (CSPRNG, not System.Random)
/// </summary>
public sealed class MfaProvider
{
    // SECURITY: Constants for TOTP and recovery codes
    public const int TotpSecretLength = 32;      // 256 bits for TOTP secret
    public const int RecoveryCodeLength = 8;     // 8 characters per recovery code
    public const int RecoveryCodeCount = 10;     // 10 backup codes generated
    public const int TotpCodeLength = 6;         // 6-digit TOTP codes
    public const int TotpTimeStep = 30;          // 30-second time window (RFC 6238)
    private const long UnixEpochTicks = 621355968000000000L; // Ticks for 1970-01-01 00:00:00 UTC
    
    // Recovery code character set (alphanumeric, no confusing chars like I, O, 1, 0)
    private const string RecoveryCodeCharset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private const int RecoveryCodeHashLength = 32;
    private const int Argon2MemoryCostKB = 65536;
    private const int Argon2TimeCost = 3;
    private const int Argon2Parallelism = 4;
    
    /// <summary>
    /// Generate a new TOTP secret for a user.
    /// 
    /// SECURITY (CWE-330):
    /// - Uses RandomNumberGenerator for cryptographically secure randomness
    /// - 32 bytes = 256 bits of entropy for TOTP secret
    /// </summary>
    /// <returns>Base32-encoded TOTP secret (suitable for QR codes)</returns>
    public static string GenerateTotpSecret()
    {
        // SECURITY: Generate cryptographically secure random bytes
        byte[] secretBytes = RandomNumberGenerator.GetBytes(TotpSecretLength);
        
        // SECURITY: Base32 encode for QR code compatibility
        // Base32 is standard for TOTP secrets (RFC 4648)
        return Base32Encode(secretBytes);
    }
    
    /// <summary>
    /// Verify a TOTP code against a secret.
    /// 
    /// SECURITY:
    /// - Accepts current time step and ±1 previous/next steps
    /// - Allows 30-second clock skew tolerance
    /// - Implements RFC 6238 Time-based One-Time Password algorithm
    /// </summary>
    /// <param name="totpSecretBase32">Base32-encoded TOTP secret</param>
    /// <param name="code">6-digit code from authenticator app</param>
    /// <returns>True if code is valid, false otherwise</returns>
    /// <exception cref="ArgumentException">If secret format is invalid</exception>
    public static bool VerifyTotpCode(string totpSecretBase32, string code)
    {
        if (string.IsNullOrEmpty(totpSecretBase32))
            throw new ArgumentException("TOTP secret cannot be empty", nameof(totpSecretBase32));
        
        if (string.IsNullOrEmpty(code))
            return false;
        
        // Validate code format (6 digits)
        if (code.Length != TotpCodeLength || !code.All(char.IsDigit))
            return false;
        
        try
        {
            // SECURITY: Decode Base32 secret
            byte[]? secretBytes = Base32Decode(totpSecretBase32);
            if (secretBytes == null || secretBytes.Length == 0)
                return false;
            
            // SECURITY (CWE-697): Use constant-time comparison
            // Get current time counter
            long timeCounter = GetTimeCounter();
            
            // Check current time step and ±1 previous/next (for clock skew tolerance)
            for (int i = -1; i <= 1; i++)
            {
                string generatedCode = GenerateTotpCode(secretBytes, timeCounter + i);
                
                // SECURITY: Constant-time comparison to prevent timing attacks
                if (ConstantTimeEquals(code, generatedCode))
                {
                    return true;
                }
            }
            
            return false;
        }
        catch
        {
            // Any error during verification = invalid code
            return false;
        }
    }
    
    /// <summary>
    /// Generate backup recovery codes.
    /// 
    /// SECURITY (CWE-330):
    /// - Generates 10 random 8-character alphanumeric codes
    /// - Uses RandomNumberGenerator for cryptographic randomness
    /// - Codes are returned plaintext (caller must hash before storage)
    /// </summary>
    /// <returns>List of 10 recovery codes (plaintext)</returns>
    public static List<string> GenerateRecoveryCodes()
    {
        var codes = new List<string>(RecoveryCodeCount);
        
        for (int i = 0; i < RecoveryCodeCount; i++)
        {
            // SECURITY: Generate 8 random characters from charset
            var code = new StringBuilder(RecoveryCodeLength);
            
            for (int j = 0; j < RecoveryCodeLength; j++)
            {
                // SECURITY: Use RandomNumberGenerator for each character
                byte[] randomByte = RandomNumberGenerator.GetBytes(1);
                int index = randomByte[0] % RecoveryCodeCharset.Length;
                code.Append(RecoveryCodeCharset[index]);
            }
            
            codes.Add(code.ToString());
        }
        
        return codes;
    }

    /// <summary>
    /// Hash a recovery code with Argon2id using the provided salt.
    /// </summary>
    public static byte[] HashRecoveryCode(string recoveryCode, byte[] salt)
    {
        if (string.IsNullOrWhiteSpace(recoveryCode))
            throw new ArgumentException("Recovery code cannot be empty", nameof(recoveryCode));

        if (salt == null || salt.Length == 0)
            throw new ArgumentException("Salt cannot be empty", nameof(salt));

        byte[] codeBytes = Encoding.UTF8.GetBytes(recoveryCode);
        try
        {
            using var argon2 = new Argon2id(codeBytes)
            {
                Salt = salt,
                DegreeOfParallelism = Argon2Parallelism,
                MemorySize = Argon2MemoryCostKB,
                Iterations = Argon2TimeCost
            };

            return argon2.GetBytes(RecoveryCodeHashLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(codeBytes);
        }
    }
    
    /// <summary>
    /// Get current time counter for TOTP (RFC 6238).
    /// Counter = floor(current_time / 30)
    /// </summary>
    private static long GetTimeCounter()
    {
        long unixTimestamp = (DateTime.UtcNow.Ticks - UnixEpochTicks) / 10000000L;
        return unixTimestamp / TotpTimeStep;
    }
    
    /// <summary>
    /// Generate a TOTP code for a specific time counter.
    /// Implements RFC 6238 algorithm.
    /// </summary>
    private static string GenerateTotpCode(byte[] secret, long timeCounter)
    {
        // Convert counter to 8-byte big-endian
        byte[] counterBytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(timeCounter & 0xFF);
            timeCounter >>= 8;
        }
        
        // HMAC-SHA1(secret, counter)
        byte[] hash;
        using (var hmac = new HMACSHA1(secret))
        {
            hash = hmac.ComputeHash(counterBytes);
        }
        
        // Dynamic truncation (RFC 6238 section 5.3)
        int offset = hash[hash.Length - 1] & 0x0F;
        int value = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);
        
        // Generate 6-digit code
        int code = value % 1000000;
        return code.ToString("D6");
    }
    
    /// <summary>
    /// Constant-time string comparison to prevent timing attacks (CWE-697).
    /// </summary>
    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a == null || b == null)
            return a == b;
        
        if (a.Length != b.Length)
            return false;
        
        int differences = 0;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i])
                differences++;
        }
        
        return differences == 0;
    }
    
    /// <summary>
    /// Encode bytes to Base32 string (RFC 4648).
    /// </summary>
    private static string Base32Encode(byte[] input)
    {
        if (input == null || input.Length == 0)
            return string.Empty;
        
        const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder();
        
        int bitBuffer = 0;
        int bitCount = 0;
        
        foreach (byte b in input)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitCount += 8;
            
            while (bitCount >= 5)
            {
                bitCount -= 5;
                int index = (bitBuffer >> bitCount) & 0x1F;
                sb.Append(Base32Alphabet[index]);
            }
        }
        
        // Handle remaining bits
        if (bitCount > 0)
        {
            int index = (bitBuffer << (5 - bitCount)) & 0x1F;
            sb.Append(Base32Alphabet[index]);
        }
        
        return sb.ToString();
    }
    
    /// <summary>
    /// Decode Base32 string to bytes (RFC 4648).
    /// </summary>
    private static byte[]? Base32Decode(string input)
    {
        if (string.IsNullOrEmpty(input))
            return Array.Empty<byte>();
        
        const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = new List<byte>();
        
        foreach (char c in input.ToUpperInvariant())
        {
            int value = Base32Alphabet.IndexOf(c);
            if (value < 0)
                return null; // Invalid Base32 character
            
            bits.Add((byte)value);
        }
        
        var bytes = new List<byte>();
        int bitBuffer = 0;
        int bitCount = 0;
        
        foreach (byte b in bits)
        {
            bitBuffer = (bitBuffer << 5) | b;
            bitCount += 5;
            
            if (bitCount >= 8)
            {
                bitCount -= 8;
                bytes.Add((byte)((bitBuffer >> bitCount) & 0xFF));
            }
        }
        
        return bytes.ToArray();
    }
}
