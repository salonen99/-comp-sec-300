/*
 * Password Generator Utility
 *
 * SECURITY FEATURES:
 * - Uses CSPRNG for strong password generation
 * - Wraps SecureRandom for consistent API
 * - No weak patterns or predictable sequences
 */

using System;
using SecurePasswordManager.Core.Crypto;

namespace SecurePasswordManager.Core.Utils;

/// <summary>
/// Generates strong, random passwords using CSPRNG.
///
/// This is a wrapper around SecureRandom to provide a simple,
/// easy-to-use interface for password generation.
/// </summary>
public static class PasswordGenerator
{
    /// <summary>
    /// Generate a strong password with customizable options.
    /// </summary>
    /// <param name="length">Password length (default 32, min 8, max 256)</param>
    /// <param name="uppercase">Include uppercase letters (default true)</param>
    /// <param name="lowercase">Include lowercase letters (default true)</param>
    /// <param name="digits">Include digits (default true)</param>
    /// <param name="symbols">Include symbols (default true)</param>
    /// <param name="excludeAmbiguous">Exclude ambiguous characters like 0/O, 1/l/I (default false)</param>
    /// <returns>Randomly generated strong password</returns>
    public static string GeneratePassword(
        int length = 32,
        bool uppercase = true,
        bool lowercase = true,
        bool digits = true,
        bool symbols = true,
        bool excludeAmbiguous = false)
    {
        if (length < 8)
            throw new ArgumentException("Password length must be at least 8 characters", nameof(length));

        if (length > 256)
            throw new ArgumentException("Password length must not exceed 256 characters", nameof(length));

        // Ensure at least one character type is selected
        if (!uppercase && !lowercase && !digits && !symbols)
            throw new ArgumentException("At least one character type must be selected", nameof(uppercase));

        var policy = new PasswordPolicy
        {
            MinLength = 8,
            MaxLength = 256,
            RequireUppercase = uppercase,
            RequireLowercase = lowercase,
            RequireDigits = digits,
            RequireSymbols = symbols
        };

        var sr = new SecureRandom(policy);
        return sr.GeneratePassword(length, uppercase, lowercase, digits, symbols, excludeAmbiguous);
    }
}
