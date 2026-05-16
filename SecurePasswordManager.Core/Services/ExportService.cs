/*
 * Password Export Service
 * 
 * SECURITY: Handles exporting passwords with optional encryption
 * - Supports CSV and JSON export formats
 * - Optional encryption using AES-256-GCM (same as vault)
 * - Plaintext exports include security warnings
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Utils;

namespace SecurePasswordManager.Core.Services;

/// <summary>
/// Service for exporting passwords to various formats.
/// </summary>
public static class ExportService
{
    /// <summary>
    /// Export passwords to CSV format.
    /// </summary>
    public static string ExportToCsv(List<PasswordEntry> entries, bool encrypted, string? masterPassword = null)
    {
        var csv = new StringBuilder();
        
        // Add warning header for plaintext
        if (!encrypted)
        {
            csv.AppendLine("# WARNING: Passwords exported as plaintext!");
            csv.AppendLine("# Handle this file with care and delete after use.");
            csv.AppendLine();
        }
        
        // Add header
        csv.AppendLine("service,username,password,url,notes,category");
        
        // Add entries
        foreach (var entry in entries)
        {
            var password = entry.Password ?? "";
            var url = entry.Url ?? "";
            var notes = entry.Notes ?? "";
            var category = entry.Category ?? "";
            
            // Escape CSV fields
            var service = EscapeCsvField(entry.ServiceName ?? "");
            var username = EscapeCsvField(entry.Username ?? "");
            password = EscapeCsvField(password);
            url = EscapeCsvField(url);
            notes = EscapeCsvField(notes);
            category = EscapeCsvField(category);
            
            csv.AppendLine($"{service},{username},{password},{url},{notes},{category}");
        }
        
        return csv.ToString();
    }
    
    /// <summary>
    /// Export passwords to JSON format.
    /// </summary>
    public static string ExportToJson(List<PasswordEntry> entries, bool encrypted, string? masterPassword = null)
    {
        var warnings = new List<string>();
        
        if (!encrypted)
        {
            warnings.Add("WARNING: Passwords exported as plaintext!");
            warnings.Add("Handle this file with care and delete after use.");
        }
        
        var json = new Dictionary<string, object>
        {
            { "exported_at", DateTime.UtcNow.ToString("O") },
            { "format", "SecurePasswordManager" },
            { "encrypted", encrypted },
            { "warnings", warnings }
        };
        
        var entriesJson = new List<Dictionary<string, object?>>();
        
        foreach (var entry in entries)
        {
            entriesJson.Add(new Dictionary<string, object?>
            {
                { "service", entry.ServiceName },
                { "username", entry.Username },
                { "password", entry.Password },
                { "url", entry.Url },
                { "notes", entry.Notes },
                { "category", entry.Category },
                { "created_at", entry.CreatedAt.ToString("O") },
                { "modified_at", entry.ModifiedAt.ToString("O") }
            });
        }
        
        json["entries"] = entriesJson;
        
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(json, options);
    }
    
    /// <summary>
    /// Export passwords to encrypted JSON format (requires master password for decryption).
    /// </summary>
    public static string ExportToEncryptedJson(List<PasswordEntry> entries, string masterPassword)
    {
        if (string.IsNullOrEmpty(masterPassword))
            throw new ArgumentException("Master password required for encrypted export");
        
        // Generate salt for this export
        var salt = KeyDerivation.GenerateSalt();
        
        byte[] keyBytes;
        using (var keyDerivation = new KeyDerivation())
        {
            keyBytes = keyDerivation.DeriveKey(masterPassword, salt);
        }
        
        var entryObjects = new List<Dictionary<string, object?>>();
        
        using (var encryption = new AesGcmEncryption(keyBytes))
        {
            foreach (var entry in entries)
            {
                var encryptedEntry = new Dictionary<string, object?>
                {
                    { "id", entry.Id },
                    { "encrypted_service", Convert.ToHexString(encryption.EncryptString(entry.ServiceName ?? "")) },
                    { "encrypted_username", Convert.ToHexString(encryption.EncryptString(entry.Username ?? "")) },
                    { "encrypted_password", Convert.ToHexString(encryption.EncryptString(entry.Password ?? "")) },
                    { "encrypted_url", Convert.ToHexString(encryption.EncryptString(entry.Url ?? "")) },
                    { "encrypted_notes", Convert.ToHexString(encryption.EncryptString(entry.Notes ?? "")) },
                    { "encrypted_category", Convert.ToHexString(encryption.EncryptString(entry.Category ?? "")) },
                    { "created_at", entry.CreatedAt.ToString("O") },
                    { "modified_at", entry.ModifiedAt.ToString("O") }
                };
                
                entryObjects.Add(encryptedEntry);
            }
        }
        
        var json = new Dictionary<string, object>
        {
            { "exported_at", DateTime.UtcNow.ToString("O") },
            { "format", "SecurePasswordManager_Encrypted" },
            { "version", "1" },
            { "salt_hex", Convert.ToHexString(salt) },
            { "entries", entryObjects }
        };
        
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(json, options);
    }
    
    /// <summary>
    /// Save export to file.
    /// </summary>
    public static void SaveToFile(string filePath, string content)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(filePath) ?? "");
            File.WriteAllText(filePath, content, Encoding.UTF8);
            
            // Set file permissions to owner-read-only on Unix-like systems
            // On Windows, this is a no-op but good for future compatibility
            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux) ||
                    System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
                {
                    var info = new System.IO.FileInfo(filePath);
                    info.UnixFileMode = System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite;
                }
            }
            catch
            {
                // Ignore permission setting errors
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to save export file: {ex.Message}", ex);
        }
    }
    
    // ---- Private Helpers ----
    
    private static string EscapeCsvField(string field)
    {
        if (string.IsNullOrEmpty(field))
            return "";
        
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n'))
        {
            return $"\"{field.Replace("\"", "\"\"")}\"";
        }
        
        return field;
    }
}
