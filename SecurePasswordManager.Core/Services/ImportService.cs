/*
 * Password Import Service
 * 
 * SECURITY: Handles parsing and validation of imported password data
 * - Validates all required fields before import
 * - Detects duplicate entries
 * - Supports multiple format: CSV, JSON, browser exports
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using SecurePasswordManager.Core.Models;

namespace SecurePasswordManager.Core.Services;

/// <summary>
/// Import conflict action when duplicate entries are detected.
/// </summary>
public enum ImportConflictAction
{
    Skip,
    Overwrite,
    KeepBoth
}

/// <summary>
/// Service for importing passwords from various formats.
/// </summary>
public static class ImportService
{
    /// <summary>
    /// Import passwords from a CSV file.
    /// Expected format: service,username,password[,url][,notes][,category]
    /// </summary>
    public static List<PasswordEntry> ImportFromCsv(string filePath)
    {
        var entries = new List<PasswordEntry>();
        
        try
        {
            var lines = File.ReadAllLines(filePath);
            
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                    continue;
                
                var parts = ParseCsvLine(line);
                if (parts.Count < 3)
                    continue; // Skip lines without minimum required fields
                
                var entry = new PasswordEntry
                {
                    ServiceName = parts[0],
                    Username = parts[1],
                    Password = parts[2],
                    Url = parts.Count > 3 ? parts[3] : null,
                    Notes = parts.Count > 4 ? parts[4] : null,
                    Category = parts.Count > 5 ? parts[5] : null,
                    CreatedAt = DateTime.UtcNow,
                    ModifiedAt = DateTime.UtcNow
                };
                
                entries.Add(entry);
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse CSV file: {ex.Message}", ex);
        }
        
        return entries;
    }
    
    /// <summary>
    /// Import passwords from a JSON file.
    /// Expects array of objects with fields: service, username, password, [url], [notes], [category]
    /// </summary>
    public static List<PasswordEntry> ImportFromJson(string filePath)
    {
        var entries = new List<PasswordEntry>();
        
        try
        {
            var json = File.ReadAllText(filePath);
            
            using (var jsonDoc = JsonDocument.Parse(json))
            {
                var root = jsonDoc.RootElement;
                
                if (root.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in root.EnumerateArray())
                    {
                        var entry = ParseJsonPasswordObject(item);
                        if (entry != null)
                            entries.Add(entry);
                    }
                }
                else if (root.ValueKind == JsonValueKind.Object)
                {
                    var entry = ParseJsonPasswordObject(root);
                    if (entry != null)
                        entries.Add(entry);
                }
            }
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Failed to parse JSON file: Invalid JSON format. {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to read JSON file: {ex.Message}", ex);
        }
        
        return entries;
    }
    
    /// <summary>
    /// Import from browser password export (auto-detect format).
    /// </summary>
    public static List<PasswordEntry> ImportFromBrowserExport(string filePath, string? browserType = null)
    {
        // Try to detect format and browser type
        var ext = Path.GetExtension(filePath).ToLower();
        
        // Try CSV first (Firefox, some others)
        if (ext == ".csv" || (browserType?.Contains("Firefox", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return ImportFromCsv(filePath);
        }
        
        // Try JSON (Chrome, 1Password, Bitwarden, others)
        if (ext == ".json" || (browserType?.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return ImportFromJson(filePath);
        }
        
        // If no extension hint, try JSON first, then CSV
        try
        {
            return ImportFromJson(filePath);
        }
        catch
        {
            // Fall back to CSV
            return ImportFromCsv(filePath);
        }
    }
    
    /// <summary>
    /// Detect duplicate entries in vault by service name.
    /// </summary>
    public static Dictionary<int, string> DetectDuplicates(List<PasswordEntry> importedEntries, List<PasswordEntry> vaultEntries)
    {
        var duplicates = new Dictionary<int, string>();
        var vaultServices = new HashSet<string>(vaultEntries.Select(e => e.ServiceName ?? ""), StringComparer.OrdinalIgnoreCase);
        
        for (int i = 0; i < importedEntries.Count; i++)
        {
            if (vaultServices.Contains(importedEntries[i].ServiceName ?? ""))
            {
                duplicates[i] = importedEntries[i].ServiceName ?? "Unknown";
            }
        }
        
        return duplicates;
    }
    
    // ---- Private Helpers ----
    
    private static List<string> ParseCsvLine(string line)
    {
        var result = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        
        for (int i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            
            if (ch == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (ch == ',' && !inQuotes)
            {
                result.Add(current.ToString().Trim('"').Trim());
                current.Clear();
            }
            else
            {
                current.Append(ch);
            }
        }
        
        result.Add(current.ToString().Trim('"').Trim());
        return result;
    }
    
    private static PasswordEntry? ParseJsonPasswordObject(JsonElement obj)
    {
        if (obj.ValueKind != JsonValueKind.Object)
            return null;
        
        // Look for common field names used by different password managers
        string? service = null, username = null, password = null, url = null, notes = null, category = null;
        
        foreach (var prop in obj.EnumerateObject())
        {
            var key = prop.Name.ToLower();
            var value = prop.Value.GetString() ?? "";
            
            // Service name field (various names)
            if (key == "service" || key == "name" || key == "title" || key == "website")
                service = value;
            
            // Username field
            else if (key == "username" || key == "user" || key == "email" || key == "login")
                username = value;
            
            // Password field
            else if (key == "password" || key == "pwd" || key == "pass")
                password = value;
            
            // URL field
            else if (key == "url" || key == "website" || key == "uri")
                url = value;
            
            // Notes field
            else if (key == "notes" || key == "note" || key == "comments")
                notes = value;
            
            // Category field
            else if (key == "category" || key == "folder" || key == "group")
                category = value;
        }
        
        // Validate required fields
        if (string.IsNullOrWhiteSpace(service) || string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return null;
        
        return new PasswordEntry
        {
            ServiceName = service,
            Username = username,
            Password = password,
            Url = string.IsNullOrWhiteSpace(url) ? null : url,
            Notes = string.IsNullOrWhiteSpace(notes) ? null : notes,
            Category = string.IsNullOrWhiteSpace(category) ? null : category,
            CreatedAt = DateTime.UtcNow,
            ModifiedAt = DateTime.UtcNow
        };
    }
}
