/*
 * Unit Tests for Password Export Service
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Services;
using Xunit;

namespace SecurePasswordManager.Tests;

/// <summary>
/// Tests for export service CSV, JSON, and encrypted export functionality.
/// </summary>
public class ExportServiceTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "ExportServiceTests_" + Guid.NewGuid());
    
    public ExportServiceTests()
    {
        Directory.CreateDirectory(_tempDir);
    }
    
    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }
    
    private List<PasswordEntry> GetTestEntries()
    {
        return new List<PasswordEntry>
        {
            new()
            {
                Id = 1,
                ServiceName = "github.com",
                Username = "user@example.com",
                Password = "password123",
                Url = "https://github.com",
                Notes = "Primary account",
                Category = "Work",
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            },
            new()
            {
                Id = 2,
                ServiceName = "twitter",
                Username = "twitteruser",
                Password = "twitterpass",
                Url = null,
                Notes = null,
                Category = "Social Media",
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            }
        };
    }
    
    [Fact]
    public void ExportToCsv_Plaintext_IncludesWarning()
    {
        var entries = GetTestEntries();
        
        var csv = ExportService.ExportToCsv(entries, encrypted: false);
        
        Assert.Contains("WARNING: Passwords exported as plaintext", csv);
        Assert.Contains("github.com", csv);
        Assert.Contains("user@example.com", csv);
        Assert.Contains("password123", csv);
    }
    
    [Fact]
    public void ExportToCsv_WithCommas_EscapesFields()
    {
        var entries = new List<PasswordEntry>
        {
            new()
            {
                ServiceName = "My App, Inc",
                Username = "user,name",
                Password = "pass,word",
                Url = null,
                Notes = null,
                Category = null,
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            }
        };
        
        var csv = ExportService.ExportToCsv(entries, encrypted: false);
        
        Assert.Contains("\"My App, Inc\"", csv);
        Assert.Contains("\"user,name\"", csv);
        Assert.Contains("\"pass,word\"", csv);
    }
    
    [Fact]
    public void ExportToCsv_Encrypted_NoWarning()
    {
        var entries = GetTestEntries();
        
        var csv = ExportService.ExportToCsv(entries, encrypted: true);
        
        Assert.DoesNotContain("WARNING", csv);
        Assert.Contains("github.com", csv);
    }
    
    [Fact]
    public void ExportToJson_Plaintext_IncludesWarning()
    {
        var entries = GetTestEntries();
        
        var json = ExportService.ExportToJson(entries, encrypted: false);
        
        Assert.Contains("WARNING", json);
        Assert.Contains("github.com", json);
    }
    
    [Fact]
    public void ExportToJson_Plaintext_ValidStructure()
    {
        var entries = GetTestEntries();
        
        var json = ExportService.ExportToJson(entries, encrypted: false);
        
        using (var doc = JsonDocument.Parse(json))
        {
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("exported_at", out _));
            Assert.True(root.TryGetProperty("format", out _));
            Assert.True(root.TryGetProperty("encrypted", out var encryptedProp));
            Assert.False(encryptedProp.GetBoolean());
            Assert.True(root.TryGetProperty("entries", out var entriesProp));
            Assert.Equal(2, entriesProp.GetArrayLength());
        }
    }
    
    [Fact]
    public void ExportToEncryptedJson_EncryptsFields()
    {
        var entries = GetTestEntries();
        var masterPassword = "MyMasterPassword123!";
        
        var json = ExportService.ExportToEncryptedJson(entries, masterPassword);
        
        // Should not contain plaintext passwords
        Assert.DoesNotContain("password123", json);
        Assert.DoesNotContain("github.com", json);
        
        // Should contain encryption metadata
        Assert.Contains("salt_hex", json);
        Assert.Contains("encrypted_password", json);
    }
    
    [Fact]
    public void ExportToEncryptedJson_ValidStructure()
    {
        var entries = GetTestEntries();
        var masterPassword = "MyMasterPassword123!";
        
        var json = ExportService.ExportToEncryptedJson(entries, masterPassword);
        
        using (var doc = JsonDocument.Parse(json))
        {
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("salt_hex", out var saltProp));
            Assert.NotNull(saltProp.GetString());
            Assert.True(root.TryGetProperty("format", out var formatProp));
            Assert.Equal("SecurePasswordManager_Encrypted", formatProp.GetString());
            Assert.True(root.TryGetProperty("entries", out var entriesProp));
            Assert.Equal(2, entriesProp.GetArrayLength());
        }
    }
    
    [Fact]
    public void ExportToEncryptedJson_EmptyPassword_Throws()
    {
        var entries = GetTestEntries();
        
        Assert.Throws<ArgumentException>(() => ExportService.ExportToEncryptedJson(entries, ""));
    }
    
    [Fact]
    public void SaveToFile_CreatesFile()
    {
        var filePath = Path.Combine(_tempDir, "export.csv");
        var content = "test,content,here";
        
        ExportService.SaveToFile(filePath, content);
        
        Assert.True(File.Exists(filePath));
        var fileContent = File.ReadAllText(filePath);
        Assert.Equal(content, fileContent);
    }
    
    [Fact]
    public void SaveToFile_CreatesDirectory()
    {
        var filePath = Path.Combine(_tempDir, "subdir", "export.json");
        var content = "test content";
        
        ExportService.SaveToFile(filePath, content);
        
        Assert.True(File.Exists(filePath));
        Assert.True(Directory.Exists(Path.GetDirectoryName(filePath)));
    }
    
    [Fact]
    public void SaveToFile_OverwritesExisting()
    {
        var filePath = Path.Combine(_tempDir, "export.csv");
        
        ExportService.SaveToFile(filePath, "original content");
        ExportService.SaveToFile(filePath, "new content");
        
        var fileContent = File.ReadAllText(filePath);
        Assert.Equal("new content", fileContent);
    }
    
    [Fact]
    public void ExportToCsv_EmptyEntries_HasHeader()
    {
        var entries = new List<PasswordEntry>();
        
        var csv = ExportService.ExportToCsv(entries, encrypted: false);
        
        Assert.Contains("service,username,password", csv);
    }
    
    [Fact]
    public void ExportToJson_EmptyEntries_ValidStructure()
    {
        var entries = new List<PasswordEntry>();
        
        var json = ExportService.ExportToJson(entries, encrypted: false);
        
        using (var doc = JsonDocument.Parse(json))
        {
            var root = doc.RootElement;
            Assert.True(root.TryGetProperty("entries", out var entriesProp));
            Assert.Equal(0, entriesProp.GetArrayLength());
        }
    }
}
