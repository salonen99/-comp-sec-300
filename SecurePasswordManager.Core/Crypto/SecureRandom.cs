/*
 * Secure Random Password Generator
 * 
 * SECURITY FEATURES (OWASP/SANS Compliance):
 * - CWE-330: Uses RandomNumberGenerator (OS CSPRNG) instead of System.Random
 * - CWE-338: Cryptographically secure pseudorandom number generator
 * - Generates high-entropy passwords with configurable complexity
 * 
 * Why RandomNumberGenerator?
 * - Based on OS CSPRNG (CryptGenRandom on Windows, /dev/urandom on Linux)
 * - Designed for cryptographic purposes
 * - System.Random is NOT secure (uses predictable algorithm)
 */

using System.Security.Cryptography;
using System.Text;

namespace SecurePasswordManager.Core.Crypto;

/// <summary>
/// Password generation policy configuration.
/// 
/// SECURITY:
/// Defines minimum requirements for generated passwords
/// to ensure adequate entropy.
/// </summary>
public record PasswordPolicy
{
    public int MinLength { get; init; } = 16;
    public int MaxLength { get; init; } = 128;
    public bool RequireUppercase { get; init; } = true;
    public bool RequireLowercase { get; init; } = true;
    public bool RequireDigits { get; init; } = true;
    public bool RequireSymbols { get; init; } = true;
    public double MinEntropyBits { get; init; } = 60.0;
}

/// <summary>
/// Cryptographically secure random password generator.
/// 
/// SECURITY NOTES:
/// - Uses RandomNumberGenerator exclusively (never System.Random)
/// - Ensures minimum entropy requirements
/// - Character selection uses secure random for uniform distribution
/// </summary>
public sealed class SecureRandom
{
    // SECURITY: Character sets for password generation
    private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    private const string Digits = "0123456789";
    private const string Symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    // SECURITY: Ambiguous characters that may cause confusion
    private const string Ambiguous = "0O1lI|";
    
    private readonly PasswordPolicy _policy;
    
    public SecureRandom(PasswordPolicy? policy = null)
    {
        _policy = policy ?? new PasswordPolicy();
    }
    
    /// <summary>
    /// Generate a cryptographically secure random password.
    /// 
    /// SECURITY (CWE-330, CWE-338):
    /// - Uses RandomNumberGenerator for uniform random selection
    /// - Ensures at least one character from each required set
    /// - Validates entropy meets minimum requirements
    /// </summary>
    public string GeneratePassword(
        int length = 16,
        bool uppercase = true,
        bool lowercase = true,
        bool digits = true,
        bool symbols = true,
        bool excludeAmbiguous = false,
        string excludeChars = "")
    {
        // SECURITY (CWE-20): Validate length
        if (length < _policy.MinLength)
        {
            throw new ArgumentException(
                $"Password length must be at least {_policy.MinLength} characters");
        }
        
        if (length > _policy.MaxLength)
        {
            throw new ArgumentException(
                $"Password length cannot exceed {_policy.MaxLength} characters");
        }
        
        // SECURITY: Build character pool
        var charPoolBuilder = new StringBuilder();
        var requiredSets = new List<string>();
        
        if (uppercase)
        {
            string chars = RemoveChars(Uppercase, excludeAmbiguous ? Ambiguous : "", excludeChars);
            charPoolBuilder.Append(chars);
            if (!string.IsNullOrEmpty(chars))
                requiredSets.Add(chars);
        }
        
        if (lowercase)
        {
            string chars = RemoveChars(Lowercase, excludeAmbiguous ? Ambiguous : "", excludeChars);
            charPoolBuilder.Append(chars);
            if (!string.IsNullOrEmpty(chars))
                requiredSets.Add(chars);
        }
        
        if (digits)
        {
            string chars = RemoveChars(Digits, excludeAmbiguous ? Ambiguous : "", excludeChars);
            charPoolBuilder.Append(chars);
            if (!string.IsNullOrEmpty(chars))
                requiredSets.Add(chars);
        }
        
        if (symbols)
        {
            string chars = RemoveChars(Symbols, excludeAmbiguous ? Ambiguous : "", excludeChars);
            charPoolBuilder.Append(chars);
            if (!string.IsNullOrEmpty(chars))
                requiredSets.Add(chars);
        }
        
        string charPool = charPoolBuilder.ToString();
        
        // SECURITY: Ensure we have enough character diversity
        if (string.IsNullOrEmpty(charPool))
        {
            throw new ArgumentException("No characters available for password generation");
        }
        
        if (charPool.Length < 10)
        {
            throw new ArgumentException(
                $"Character pool too small ({charPool.Length} chars). " +
                "Reduce exclusions or enable more character types.");
        }
        
        // SECURITY: Calculate and verify entropy
        double entropy = CalculateEntropy(charPool.Length, length);
        if (entropy < _policy.MinEntropyBits)
        {
            throw new ArgumentException(
                $"Password entropy ({entropy:F1} bits) is below minimum " +
                $"({_policy.MinEntropyBits} bits). Increase length or character types.");
        }
        
        // SECURITY: Generate password ensuring all required character types
        return GenerateWithRequirements(charPool, requiredSets, length);
    }
    
    private static string GenerateWithRequirements(
        string charPool, 
        List<string> requiredSets, 
        int length)
    {
        char[] password = new char[length];
        int position = 0;
        
        // SECURITY: Add at least one character from each required set
        foreach (string charSet in requiredSets)
        {
            password[position++] = SecureChoice(charSet);
        }
        
        // SECURITY: Fill remaining positions with random characters
        while (position < length)
        {
            password[position++] = SecureChoice(charPool);
        }
        
        // SECURITY: Shuffle to prevent predictable positions
        SecureShuffle(password);
        
        return new string(password);
    }
    
    /// <summary>
    /// Cryptographically secure character selection.
    /// 
    /// SECURITY: Uses rejection sampling for uniform distribution.
    /// </summary>
    private static char SecureChoice(string chars)
    {
        // SECURITY: Use rejection sampling to avoid modulo bias
        int maxValid = (256 / chars.Length) * chars.Length;
        
        Span<byte> randomByte = stackalloc byte[1];
        int index;
        
        do
        {
            RandomNumberGenerator.Fill(randomByte);
            index = randomByte[0];
        } while (index >= maxValid);
        
        return chars[index % chars.Length];
    }
    
    /// <summary>
    /// Cryptographically secure Fisher-Yates shuffle.
    /// 
    /// SECURITY (CWE-330):
    /// Uses RandomNumberGenerator for random index generation.
    /// </summary>
    private static void SecureShuffle(char[] array)
    {
        for (int i = array.Length - 1; i > 0; i--)
        {
            int j = SecureRandomInt(i + 1);
            (array[i], array[j]) = (array[j], array[i]);
        }
    }
    
    /// <summary>
    /// Generate a cryptographically secure random integer.
    /// </summary>
    private static int SecureRandomInt(int exclusiveUpperBound)
    {
        // SECURITY: RandomNumberGenerator.GetInt32 handles rejection sampling
        return RandomNumberGenerator.GetInt32(exclusiveUpperBound);
    }
    
    /// <summary>
    /// Calculate password entropy in bits.
    /// 
    /// SECURITY:
    /// Entropy = log2(pool_size^length) = length * log2(pool_size)
    /// 
    /// Higher entropy = more secure password
    /// - 60 bits: Decent for most uses
    /// - 80 bits: Good security
    /// - 128 bits: Very high security
    /// </summary>
    public static double CalculateEntropy(int poolSize, int length)
    {
        if (poolSize <= 1) return 0.0;
        return length * Math.Log2(poolSize);
    }
    
    private static string RemoveChars(string source, params string[] toRemove)
    {
        var result = new StringBuilder(source.Length);
        var removeSet = new HashSet<char>(string.Concat(toRemove));
        
        foreach (char c in source)
        {
            if (!removeSet.Contains(c))
            {
                result.Append(c);
            }
        }
        
        return result.ToString();
    }
    
    /// <summary>
    /// Generate a passphrase using random words.
    /// 
    /// SECURITY:
    /// Passphrases are easier to remember while maintaining high entropy.
    /// 4 words from a 7776-word list = ~51 bits of entropy
    /// 6 words = ~77 bits of entropy
    /// </summary>
    public string GeneratePassphrase(
        int wordCount = 4,
        string separator = "-",
        bool capitalize = true)
    {
        if (wordCount < 4)
        {
            throw new ArgumentException("Passphrase must have at least 4 words");
        }
        
        string[] words = GetWordlist();
        var selected = new string[wordCount];
        
        for (int i = 0; i < wordCount; i++)
        {
            int index = RandomNumberGenerator.GetInt32(words.Length);
            string word = words[index];
            selected[i] = capitalize ? char.ToUpper(word[0]) + word[1..] : word;
        }
        
        return string.Join(separator, selected);
    }
    
    /// <summary>
    /// Generate a cryptographically secure random token.
    /// 
    /// SECURITY (CWE-330):
    /// Uses RandomNumberGenerator for cryptographic randomness.
    /// Suitable for API keys, session tokens, etc.
    /// </summary>
    public static string GenerateToken(int length = 32)
    {
        if (length < 16)
        {
            throw new ArgumentException("Token must be at least 16 characters");
        }
        
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(length / 2)).ToLowerInvariant();
    }
    
    /// <summary>
    /// Generate cryptographically secure random bytes.
    /// </summary>
    public static byte[] GenerateBytes(int length = 32)
    {
        if (length < 16)
        {
            throw new ArgumentException("Must generate at least 16 bytes");
        }
        
        return RandomNumberGenerator.GetBytes(length);
    }
    
    private static string[] GetWordlist()
    {
        // SECURITY NOTE: This is a subset of the EFF short wordlist.
        // In production, use the full 7776-word list for better entropy.
        return
        [
            "apple", "banana", "cherry", "dragon", "elephant", "falcon",
            "guitar", "harbor", "island", "jungle", "kitchen", "lemon",
            "mountain", "notebook", "ocean", "penguin", "quantum", "river",
            "sunset", "thunder", "umbrella", "volcano", "whisper", "yellow",
            "zebra", "anchor", "bridge", "castle", "dolphin", "emerald",
            "forest", "glacier", "horizon", "iceberg", "jasmine", "koala",
            "lantern", "marble", "nebula", "orchid", "pyramid", "quartz",
            "rainbow", "sapphire", "tornado", "unicorn", "velvet", "waterfall",
            "crystal", "diamond", "eclipse", "feather", "galaxy", "harmony",
            "infinity", "journey", "kingdom", "liberty", "mystery", "nirvana",
            "paradise", "silence", "twilight", "voyage", "wonder", "zenith",
            "blossom", "courage", "destiny", "freedom", "grateful", "inspire",
            "miracle", "phoenix", "radiant", "serenity", "treasure", "wisdom",
            "blanket", "captain", "explore", "gravity", "harvest", "justice",
            "kindred", "meadow", "oracle", "pioneer", "stellar", "triumph",
            "vintage", "warrior", "balance", "carnival", "eternal", "flutter",
            "golden", "hunter", "legend", "maestro", "nimble", "odyssey"
        ];
    }
}
