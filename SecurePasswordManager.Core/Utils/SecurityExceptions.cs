/*
 * Secure Exception Handling
 * 
 * SECURITY (CWE-209, CWE-537 - Information Exposure Through Error Messages):
 * - Custom exceptions that don't expose sensitive information
 * - Detailed logging for developers only
 * - User-friendly error messages without implementation details
 * - Never include passwords, keys, or paths in error messages to users
 */

using System.Diagnostics;

namespace SecurePasswordManager.Core.Utils;

/// <summary>
/// Base class for vault exceptions that handles both detailed logging
/// and user-safe error messages.
/// </summary>
public class VaultException : Exception
{
    /// <summary>
    /// User-safe error message (shown to end user).
    /// </summary>
    public string UserMessage { get; }
    
    /// <summary>
    /// Detailed error message (logged for debugging, never shown to user).
    /// </summary>
    public string DetailedMessage { get; }
    
    /// <summary>
    /// Initialize vault exception with both user-safe and detailed messages.
    /// </summary>
    /// <param name="userMessage">Message shown to end user (no sensitive data)</param>
    /// <param name="detailedMessage">Detailed message for logging only</param>
    /// <param name="innerException">Inner exception if applicable</param>
    public VaultException(string userMessage, string detailedMessage, Exception? innerException = null)
        : base(userMessage, innerException)
    {
        UserMessage = userMessage;
        DetailedMessage = detailedMessage;
        
        // SECURITY: Log detailed message for diagnostic purposes only
        LogDetailedError(detailedMessage, innerException);
    }
    
    /// <summary>
    /// SECURITY (CWE-215): Log detailed error information for developers only.
    /// In production, this should write to a secure audit log, not console.
    /// </summary>
    private static void LogDetailedError(string detailedMessage, Exception? innerException)
    {
        // SECURITY: Only log to debug output, not shown to user
        Debug.WriteLine($"[VAULT ERROR] {detailedMessage}");
        if (innerException != null)
        {
            Debug.WriteLine($"[INNER EXCEPTION] {innerException}");
        }
    }
}

/// <summary>
/// Thrown when master password is invalid.
/// </summary>
public class InvalidMasterPasswordException : VaultException
{
    public InvalidMasterPasswordException(string detailedReason)
        : base(
            userMessage: "Master password is invalid or incorrect.",
            detailedMessage: detailedReason)
    {
    }
}

/// <summary>
/// Thrown when vault operations fail due to invalid data.
/// </summary>
public class InvalidVaultDataException : VaultException
{
    public InvalidVaultDataException(string detailedReason)
        : base(
            userMessage: "Vault data is corrupted or invalid.",
            detailedMessage: detailedReason)
    {
    }
}

/// <summary>
/// Thrown when vault is locked but operation requires it to be unlocked.
/// </summary>
public class VaultLockedException : VaultException
{
    public VaultLockedException()
        : base(
            userMessage: "Vault is locked. Please unlock it first.",
            detailedMessage: "Operation attempted on locked vault")
    {
    }
}

/// <summary>
/// Thrown when vault file is not found.
/// </summary>
public class VaultFileNotFoundException : VaultException
{
    public VaultFileNotFoundException(string vaultPath)
        : base(
            userMessage: "Vault file not found.",
            detailedMessage: $"Vault file not found at: {vaultPath}")
    {
    }
}

/// <summary>
/// Thrown when vault creation fails.
/// </summary>
public class VaultCreationException : VaultException
{
    public VaultCreationException(string detailedReason)
        : base(
            userMessage: "Failed to create vault. Please check your disk space and permissions.",
            detailedMessage: detailedReason)
    {
    }
}

/// <summary>
/// Thrown when a security violation is detected (e.g., concurrent vault access).
/// </summary>
public class SecurityException : VaultException
{
    public SecurityException(string userMessage, Exception? innerException = null)
        : base(
            userMessage: userMessage,
            detailedMessage: userMessage,
            innerException: innerException)
    {
    }
}

/// <summary>
/// Helper class for secure error handling.
/// </summary>
public static class ErrorHandling
{
    /// <summary>
    /// Execute an operation with secure error handling.
    /// 
    /// SECURITY: Catches and converts exceptions to user-safe messages.
    /// </summary>
    public static async Task<T> ExecuteSecureAsync<T>(
        Func<Task<T>> operation,
        string operationName)
    {
        try
        {
            return await operation();
        }
        catch (VaultException)
        {
            throw;  // Re-throw custom exceptions as-is
        }
        catch (FileNotFoundException ex)
        {
            throw new VaultFileNotFoundException(ex.FileName ?? "unknown");
        }
        catch (IOException ex)
        {
            throw new VaultException(
                userMessage: "A disk error occurred. Please check your disk space and permissions.",
                detailedMessage: $"IO error during {operationName}: {ex.Message}",
                innerException: ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new VaultException(
                userMessage: "You do not have permission to access the vault.",
                detailedMessage: $"Permission denied during {operationName}: {ex.Message}",
                innerException: ex);
        }
        catch (Exception ex)
        {
            throw new VaultException(
                userMessage: $"An unexpected error occurred during {operationName}.",
                detailedMessage: $"Unexpected error: {ex.GetType().Name}: {ex.Message}",
                innerException: ex);
        }
    }
    
    /// <summary>
    /// Execute an operation with secure error handling (non-async).
    /// </summary>
    public static T ExecuteSecure<T>(
        Func<T> operation,
        string operationName)
    {
        try
        {
            return operation();
        }
        catch (VaultException)
        {
            throw;  // Re-throw custom exceptions as-is
        }
        catch (FileNotFoundException ex)
        {
            throw new VaultFileNotFoundException(ex.FileName ?? "unknown");
        }
        catch (IOException ex)
        {
            throw new VaultException(
                userMessage: "A disk error occurred. Please check your disk space and permissions.",
                detailedMessage: $"IO error during {operationName}: {ex.Message}",
                innerException: ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new VaultException(
                userMessage: "You do not have permission to access the vault.",
                detailedMessage: $"Permission denied during {operationName}: {ex.Message}",
                innerException: ex);
        }
        catch (Exception ex)
        {
            throw new VaultException(
                userMessage: $"An unexpected error occurred during {operationName}.",
                detailedMessage: $"Unexpected error: {ex.GetType().Name}: {ex.Message}",
                innerException: ex);
        }
    }
}
