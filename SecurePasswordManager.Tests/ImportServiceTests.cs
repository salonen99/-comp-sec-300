/*
 * Unit Tests for Password Import Service
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Services;
using Xunit;

namespace SecurePasswordManager.Tests;

/// <summary>
/// Tests for import service CSV, JSON, and browser export parsing.
/// </summary>
public class ImportServiceTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "ImportServiceTests_" + Guid.NewGuid());
    
    public ImportServiceTests()
    {
        Directory.CreateDirectory(_tempDir);
    }
    
    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }
    
    [Fact]
    public void ImportFromCsv_ValidFile_ParsesEntries()
    {
        var csv = "github.com,user@example.com,password123\ntwitter,twitterhandle,twitterpass\n";
        var file = Path.Combine(_tempDir, "test.csv");
        File.WriteAllText(file, csv);
        
        var entries = ImportService.ImportFromCsv(file);
        
        Assert.Equal(2, entries.Count);
        Assert.Equal("github.com", entries[0].ServiceName);
        Assert.Equal("user@example.com", entries[0].Username);
        Assert.Equal("password123", entries[0].Password);
    }
    
    [Fact]
    public void ImportFromCsv_WithOptionalFields_ParsesAll()
    {
        var csv = "github.com,user@example.com,password123,https://github.com,Work account,Work\n";
        var file = Path.Combine(_tempDir, "test_full.csv");
        File.WriteAllText(file, csv);
        
        var entries = ImportService.ImportFromCsv(file);
        
        Assert.Single(entries);
        Assert.Equal("https://github.com", entries[0].Url);
        Assert.Equal("Work account", entries[0].Notes);
        Assert.Equal("Work", entries[0].Category);
    }
    
    [Fact]
    public void ImportFromCsv_WithQuotedFields_ParsesCorrectly()
    {
        var csv = "\"github.com\",\"user@example.com\",\"pass,with,commas\"\n";
        var file = Path.Combine(_tempDir, "test_quoted.csv");
        File.WriteAllText(file, csv);
        
        var entries = ImportService.ImportFromCsv(file);
        
        Assert.Single(entries);
        Assert.Equal("github.com", entries[0].ServiceName);
        Assert.Equal("pass,with,commas", entries[0].Password);
    }
    
    [Fact]
    public void ImportFromCsv_SkipsComments_AndEmptyLines()
    {
        var csv = "# Comment line\n\ngithub.com,user,pass\n\n# Another comment\ntwitter,user2,pass2\n";
        var file = Path.Combine(_tempDir, "test_comments.csv");
        File.WriteAllText(file, csv);
        
        var entries = ImportService.ImportFromCsv(file);
        
        Assert.Equal(2, entries.Count);
    }
    
    [Fact]
    public void ImportFromCsv_MissingRequiredFields_SkipsEntry()
    {
        var csv = "github.com,user@example.com\ngithub.com,user,pass\n";
        var file = Path.Combine(_tempDir, "test_incomplete.csv");
        File.WriteAllText(file, csv);
        
        var entries = ImportService.ImportFromCsv(file);
        
        Assert.Single(entries);
        Assert.Equal("github.com", entries[0].ServiceName);
    }
    
    [Fact]
    public void ImportFromCsv_InvalidFile_ThrowsException()
    {
        var file = Path.Combine(_tempDir, "nonexistent.csv");
        
        Assert.Throws<InvalidOperationException>(() => ImportService.ImportFromCsv(file));
    }
    
    [Fact]
    public void ImportFromJson_ValidArray_ParsesEntries()
    {
        var json = @"[
            { ""service"": ""github.com"", ""username"": ""user@example.com"", ""password"": ""pass123"" },
            { ""service"": ""twitter"", ""username"": ""twitterhandle"", ""password"": ""pass456"" }
        ]";
        var file = Path.Combine(_tempDir, "test.json");
        File.WriteAllText(file, json);
        
        var entries = ImportService.ImportFromJson(file);
        
        Assert.Equal(2, entries.Count);
        Assert.Equal("github.com", entries[0].ServiceName);
        Assert.Equal("pass123", entries[0].Password);
    }
    
    [Fact]
    public void ImportFromJson_WithOptionalFields_ParsesAll()
    {
        var json = @"{
            ""service"": ""github.com"",
            ""username"": ""user@example.com"",
            ""password"": ""pass123"",
            ""url"": ""https://github.com"",
            ""notes"": ""Primary account"",
            ""category"": ""Work""
        }";
        var file = Path.Combine(_tempDir, "test_single.json");
        File.WriteAllText(file, json);
        
        var entries = ImportService.ImportFromJson(file);
        
        Assert.Single(entries);
        Assert.Equal("https://github.com", entries[0].Url);
        Assert.Equal("Primary account", entries[0].Notes);
        Assert.Equal("Work", entries[0].Category);
    }
    
    [Fact]
    public void ImportFromJson_AlternateFieldNames_ParsesCorrectly()
    {
        // Test browser export style field names
        var json = @"[
            { ""name"": ""github.com"", ""login"": ""user@example.com"", ""password"": ""pass123"" },
            { ""title"": ""twitter"", ""email"": ""user@twitter.com"", ""pwd"": ""pass456"" }
        ]";
        var file = Path.Combine(_tempDir, "test_alt_names.json");
        File.WriteAllText(file, json);
        
        var entries = ImportService.ImportFromJson(file);
        
        Assert.Equal(2, entries.Count);
        Assert.Equal("github.com", entries[0].ServiceName);
        Assert.Equal("user@twitter.com", entries[1].Username);
    }
    
    [Fact]
    public void ImportFromJson_InvalidJson_ThrowsException()
    {
        var json = "{ invalid json }";
        var file = Path.Combine(_tempDir, "invalid.json");
        File.WriteAllText(file, json);
        
        Assert.Throws<InvalidOperationException>(() => ImportService.ImportFromJson(file));
    }
    
    [Fact]
    public void ImportFromJson_MissingRequiredFields_SkipsEntry()
    {
        var json = @"[
            { ""service"": ""github.com"", ""username"": ""user"" },
            { ""service"": ""twitter"", ""username"": ""user"", ""password"": ""pass"" }
        ]";
        var file = Path.Combine(_tempDir, "incomplete.json");
        File.WriteAllText(file, json);
        
        var entries = ImportService.ImportFromJson(file);
        
        Assert.Single(entries);
        Assert.Equal("twitter", entries[0].ServiceName);
    }
    
    [Fact]
    public void DetectDuplicates_FindsMatchingServices()
    {
        var imported = new List<PasswordEntry>
        {
            new() { ServiceName = "github.com", Username = "new_user", Password = "newpass" },
            new() { ServiceName = "twitter", Username = "new_user", Password = "newpass" }
        };
        
        var vault = new List<PasswordEntry>
        {
            new() { ServiceName = "github.com", Username = "old_user", Password = "oldpass" }
        };
        
        var duplicates = ImportService.DetectDuplicates(imported, vault);
        
        Assert.Single(duplicates);
        Assert.Contains(0, duplicates.Keys);
        Assert.Equal("github.com", duplicates[0]);
    }
    
    [Fact]
    public void DetectDuplicates_CaseInsensitive()
    {
        var imported = new List<PasswordEntry>
        {
            new() { ServiceName = "GITHUB.COM", Username = "user", Password = "pass" }
        };
        
        var vault = new List<PasswordEntry>
        {
            new() { ServiceName = "github.com", Username = "user", Password = "pass" }
        };
        
        var duplicates = ImportService.DetectDuplicates(imported, vault);
        
        Assert.Single(duplicates);
    }
    
    [Fact]
    public void DetectDuplicates_NoDuplicates()
    {
        var imported = new List<PasswordEntry>
        {
            new() { ServiceName = "newapp.com", Username = "user", Password = "pass" }
        };
        
        var vault = new List<PasswordEntry>
        {
            new() { ServiceName = "github.com", Username = "user", Password = "pass" }
        };
        
        var duplicates = ImportService.DetectDuplicates(imported, vault);
        
        Assert.Empty(duplicates);
    }
    
    [Fact]
    public void ImportFromBrowserExport_CsvExtension_ParsesAsCsv()
    {
        var csv = "github.com,user,pass\n";
        var file = Path.Combine(_tempDir, "export.csv");
        File.WriteAllText(file, csv);
        
        var entries = ImportService.ImportFromBrowserExport(file);
        
        Assert.Single(entries);
        Assert.Equal("github.com", entries[0].ServiceName);
    }
    
    [Fact]
    public void ImportFromBrowserExport_JsonExtension_ParsesAsJson()
    {
        var json = @"[{ ""service"": ""github.com"", ""username"": ""user"", ""password"": ""pass"" }]";
        var file = Path.Combine(_tempDir, "export.json");
        File.WriteAllText(file, json);
        
        var entries = ImportService.ImportFromBrowserExport(file);
        
        Assert.Single(entries);
        Assert.Equal("github.com", entries[0].ServiceName);
    }
    
    [Fact]
    public void ImportFromBrowserExport_BrowserTypeHint_UsesCorrectFormat()
    {
        var json = @"[{ ""service"": ""github.com"", ""username"": ""user"", ""password"": ""pass"" }]";
        var file = Path.Combine(_tempDir, "chrome_export.dat");
        File.WriteAllText(file, json);
        
        var entries = ImportService.ImportFromBrowserExport(file, "Chrome");
        
        Assert.Single(entries);
        Assert.Equal("github.com", entries[0].ServiceName);
    }
}
