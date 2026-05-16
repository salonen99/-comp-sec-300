/*
 * Input Validation Module
 * 
 * SECURITY FEATURES (OWASP/SANS Compliance):
 * - CWE-20: Improper Input Validation - All inputs validated
 * - CWE-89: SQL Injection - Length limits prevent buffer issues
 * - Whitelist validation for allowed characters
 * - Length limits on all fields
 * 
 * Validation Strategy:
 * - Fail-fast: Reject invalid input immediately
 * - Whitelist: Only allow explicitly permitted characters
 * - Length limits: Prevent resource exhaustion and buffer issues
 */

using System.Text.RegularExpressions;

namespace SecurePasswordManager.Core.Utils;

/// <summary>
/// Validation result with detailed error information.
/// </summary>
public sealed partial class ValidationResult
{
    public bool IsValid { get; }
    public string? ErrorMessage { get; }
    public string? FieldName { get; }
    
    private ValidationResult(bool isValid, string? errorMessage = null, string? fieldName = null)
    {
        IsValid = isValid;
        ErrorMessage = errorMessage;
        FieldName = fieldName;
    }
    
    public static ValidationResult Success() => new(true);
    
    public static ValidationResult Failure(string errorMessage, string? fieldName = null) 
        => new(false, errorMessage, fieldName);
}

/// <summary>
/// Input validators for secure password manager.
/// 
/// SECURITY NOTES:
/// - All validators use strict whitelist approach
/// - Length limits prevent resource exhaustion
/// - Special characters are controlled to prevent injection
/// </summary>
public static partial class Validators
{
    // SECURITY: Maximum field lengths to prevent resource exhaustion
    public const int MaxServiceNameLength = 100;
    public const int MaxUsernameLength = 200;
    public const int MaxPasswordLength = 500;
    public const int MaxUrlLength = 2000;
    public const int MaxNotesLength = 10000;
    public const int MaxCategoryLength = 50;
    
    // SECURITY: Minimum master password requirements
    public const int MinMasterPasswordLength = 12;
    public const int MaxMasterPasswordLength = 128;
    
    // SECURITY: Regex patterns for validation (compiled for performance)
    // Using GeneratedRegex for AOT compatibility and better performance
    
    /// <summary>
    /// Service name: alphanumeric, spaces, and common punctuation.
    /// </summary>
    [GeneratedRegex(@"^[\p{L}\p{N}\s\-_\.@]+$", RegexOptions.Compiled)]
    private static partial Regex ServiceNamePattern();
    
    /// <summary>
    /// Username: alphanumeric, email characters.
    /// </summary>
    [GeneratedRegex(@"^[\p{L}\p{N}\s\-_\.@+]+$", RegexOptions.Compiled)]
    private static partial Regex UsernamePattern();
    
    /// <summary>
    /// URL: standard URL characters.
    /// </summary>
    [GeneratedRegex(@"^https?://[\p{L}\p{N}\-._~:/?#\[\]@!$&'()*+,;=%]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex UrlPattern();
    
    /// <summary>
    /// Category: alphanumeric and basic punctuation.
    /// </summary>
    [GeneratedRegex(@"^[\p{L}\p{N}\s\-_]+$", RegexOptions.Compiled)]
    private static partial Regex CategoryPattern();
    
    /// <summary>
    /// Validate service name.
    /// 
    /// SECURITY (CWE-20):
    /// - Length limit: 1-100 characters
    /// - Whitelist: Letters, numbers, spaces, common punctuation
    /// </summary>
    public static ValidationResult ValidateServiceName(string? serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return ValidationResult.Failure(
                "Service name is required", 
                nameof(serviceName));
        }
        
        if (serviceName.Length > MaxServiceNameLength)
        {
            return ValidationResult.Failure(
                $"Service name cannot exceed {MaxServiceNameLength} characters",
                nameof(serviceName));
        }
        
        if (!ServiceNamePattern().IsMatch(serviceName))
        {
            return ValidationResult.Failure(
                "Service name contains invalid characters",
                nameof(serviceName));
        }
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Validate username/email.
    /// 
    /// SECURITY (CWE-20):
    /// - Length limit: 1-200 characters
    /// - Whitelist: Email-compatible characters
    /// </summary>
    public static ValidationResult ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return ValidationResult.Failure(
                "Username is required",
                nameof(username));
        }
        
        if (username.Length > MaxUsernameLength)
        {
            return ValidationResult.Failure(
                $"Username cannot exceed {MaxUsernameLength} characters",
                nameof(username));
        }
        
        if (!UsernamePattern().IsMatch(username))
        {
            return ValidationResult.Failure(
                "Username contains invalid characters",
                nameof(username));
        }
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Validate password.
    /// 
    /// SECURITY (CWE-20):
    /// - Length limit: 1-500 characters
    /// - No character restrictions (passwords can contain anything)
    /// </summary>
    public static ValidationResult ValidatePassword(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return ValidationResult.Failure(
                "Password is required",
                nameof(password));
        }
        
        if (password.Length > MaxPasswordLength)
        {
            return ValidationResult.Failure(
                $"Password cannot exceed {MaxPasswordLength} characters",
                nameof(password));
        }
        
        // SECURITY: No character restrictions on passwords
        // Users may need to store passwords with any characters
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Validate URL (optional).
    /// 
    /// SECURITY (CWE-20):
    /// - Length limit: 0-2000 characters
    /// - Must be valid HTTP/HTTPS URL format
    /// </summary>
    public static ValidationResult ValidateUrl(string? url)
    {
        // URL is optional
        if (string.IsNullOrWhiteSpace(url))
        {
            return ValidationResult.Success();
        }
        
        if (url.Length > MaxUrlLength)
        {
            return ValidationResult.Failure(
                $"URL cannot exceed {MaxUrlLength} characters",
                nameof(url));
        }
        
        if (!UrlPattern().IsMatch(url))
        {
            return ValidationResult.Failure(
                "URL must be a valid HTTP or HTTPS address",
                nameof(url));
        }
        
        // SECURITY: Additional validation using Uri.TryCreate
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return ValidationResult.Failure(
                "URL must be a valid HTTP or HTTPS address",
                nameof(url));
        }
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Validate notes (optional).
    /// 
    /// SECURITY (CWE-20):
    /// - Length limit: 0-10000 characters
    /// - Allow most characters for flexibility
    /// </summary>
    public static ValidationResult ValidateNotes(string? notes)
    {
        // Notes are optional
        if (string.IsNullOrEmpty(notes))
        {
            return ValidationResult.Success();
        }
        
        if (notes.Length > MaxNotesLength)
        {
            return ValidationResult.Failure(
                $"Notes cannot exceed {MaxNotesLength} characters",
                nameof(notes));
        }
        
        // SECURITY: Check for null bytes (could indicate injection attempt)
        if (notes.Contains('\0'))
        {
            return ValidationResult.Failure(
                "Notes contain invalid characters",
                nameof(notes));
        }
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Validate category (optional).
    /// 
    /// SECURITY (CWE-20):
    /// - Length limit: 0-50 characters
    /// - Whitelist: Alphanumeric, spaces, hyphens, underscores
    /// </summary>
    public static ValidationResult ValidateCategory(string? category)
    {
        // Category is optional
        if (string.IsNullOrWhiteSpace(category))
        {
            return ValidationResult.Success();
        }
        
        if (category.Length > MaxCategoryLength)
        {
            return ValidationResult.Failure(
                $"Category cannot exceed {MaxCategoryLength} characters",
                nameof(category));
        }
        
        if (!CategoryPattern().IsMatch(category))
        {
            return ValidationResult.Failure(
                "Category contains invalid characters",
                nameof(category));
        }
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Validate master password strength.
    /// 
    /// SECURITY:
    /// - Minimum 12 characters
    /// - Maximum 128 characters
    /// - Recommends complexity but doesn't enforce
    /// </summary>
    public static ValidationResult ValidateMasterPassword(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return ValidationResult.Failure(
                "Master password is required",
                "masterPassword");
        }
        
        if (password.Length < MinMasterPasswordLength)
        {
            return ValidationResult.Failure(
                $"Master password must be at least {MinMasterPasswordLength} characters",
                "masterPassword");
        }
        
        if (password.Length > MaxMasterPasswordLength)
        {
            return ValidationResult.Failure(
                $"Master password cannot exceed {MaxMasterPasswordLength} characters",
                "masterPassword");
        }
        
        return ValidationResult.Success();
    }
    
    /// <summary>
    /// Check master password strength and return recommendations.
    /// </summary>
    public static PasswordStrength CheckMasterPasswordStrength(string password)
    {
        var strength = new PasswordStrength();
        
        if (string.IsNullOrEmpty(password))
        {
            strength.Score = 0;
            strength.Level = StrengthLevel.VeryWeak;
            return strength;
        }
        
        // Length scoring
        if (password.Length >= 16) strength.Score += 2;
        else if (password.Length >= 12) strength.Score += 1;
        
        // Character variety scoring
        if (password.Any(char.IsUpper)) strength.Score += 1;
        if (password.Any(char.IsLower)) strength.Score += 1;
        if (password.Any(char.IsDigit)) strength.Score += 1;
        if (password.Any(c => !char.IsLetterOrDigit(c))) strength.Score += 1;
        
        // Determine level
        strength.Level = strength.Score switch
        {
            >= 6 => StrengthLevel.VeryStrong,
            >= 5 => StrengthLevel.Strong,
            >= 4 => StrengthLevel.Good,
            >= 3 => StrengthLevel.Fair,
            >= 2 => StrengthLevel.Weak,
            _ => StrengthLevel.VeryWeak
        };
        
        // Add recommendations
        if (password.Length < 16)
            strength.Recommendations.Add("Use at least 16 characters");
        if (!password.Any(char.IsUpper))
            strength.Recommendations.Add("Add uppercase letters");
        if (!password.Any(char.IsLower))
            strength.Recommendations.Add("Add lowercase letters");
        if (!password.Any(char.IsDigit))
            strength.Recommendations.Add("Add numbers");
        if (!password.Any(c => !char.IsLetterOrDigit(c)))
            strength.Recommendations.Add("Add special characters");
        
        return strength;
    }
    
    /// <summary>
    /// Validate a complete password entry.
    /// </summary>
    public static List<ValidationResult> ValidateEntry(
        string? serviceName,
        string? username,
        string? password,
        string? url = null,
        string? notes = null,
        string? category = null)
    {
        var results = new List<ValidationResult>
        {
            ValidateServiceName(serviceName),
            ValidateUsername(username),
            ValidatePassword(password),
            ValidateUrl(url),
            ValidateNotes(notes),
            ValidateCategory(category)
        };
        
        return results.Where(r => !r.IsValid).ToList();
    }
}

/// <summary>
/// Password strength assessment result.
/// </summary>
public sealed class PasswordStrength
{
    public int Score { get; set; }
    public StrengthLevel Level { get; set; }
    public List<string> Recommendations { get; } = [];
}

/// <summary>
/// Password strength levels.
/// </summary>
public enum StrengthLevel
{
    VeryWeak,
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong
}
