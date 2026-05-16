/*
 * Unit Tests for Phase 2: Secure Data Storage
 * 
 * SECURITY TESTING:
 * - Input validation tests
 * - SQL injection prevention verification
 * - Database operations with encrypted data
 * - Vault service integration tests
 */

using SecurePasswordManager.Core.Database;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Services;
using SecurePasswordManager.Core.Utils;

namespace SecurePasswordManager.Tests;

/// <summary>
/// Tests for input validators.
/// 
/// SECURITY: Verifies all input validation works correctly
/// to prevent CWE-20 (Improper Input Validation).
/// </summary>
public class ValidatorTests
{
    // ==================== Service Name Tests ====================
    
    [Fact]
    public void ValidateServiceName_ValidName_ReturnsSuccess()
    {
        var result = Validators.ValidateServiceName("GitHub");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateServiceName_WithSpaces_ReturnsSuccess()
    {
        var result = Validators.ValidateServiceName("My Service Name");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateServiceName_Empty_ReturnsFalse()
    {
        var result = Validators.ValidateServiceName("");
        Assert.False(result.IsValid);
        Assert.Contains("required", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void ValidateServiceName_Null_ReturnsFalse()
    {
        var result = Validators.ValidateServiceName(null);
        Assert.False(result.IsValid);
    }
    
    [Fact]
    public void ValidateServiceName_TooLong_ReturnsFalse()
    {
        var longName = new string('a', Validators.MaxServiceNameLength + 1);
        var result = Validators.ValidateServiceName(longName);
        Assert.False(result.IsValid);
        Assert.Contains("exceed", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
    
    [Theory]
    [InlineData("Service<script>")]
    [InlineData("Service;DROP TABLE")]
    [InlineData("Service\0Name")]
    public void ValidateServiceName_InvalidChars_ReturnsFalse(string name)
    {
        var result = Validators.ValidateServiceName(name);
        Assert.False(result.IsValid);
    }
    
    // ==================== Username Tests ====================
    
    [Fact]
    public void ValidateUsername_ValidEmail_ReturnsSuccess()
    {
        var result = Validators.ValidateUsername("user@example.com");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateUsername_Empty_ReturnsFalse()
    {
        var result = Validators.ValidateUsername("");
        Assert.False(result.IsValid);
    }
    
    [Fact]
    public void ValidateUsername_TooLong_ReturnsFalse()
    {
        var longUsername = new string('a', Validators.MaxUsernameLength + 1);
        var result = Validators.ValidateUsername(longUsername);
        Assert.False(result.IsValid);
    }
    
    // ==================== Password Tests ====================
    
    [Fact]
    public void ValidatePassword_ValidPassword_ReturnsSuccess()
    {
        var result = Validators.ValidatePassword("MyS3cur3P@ssw0rd!");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidatePassword_Empty_ReturnsFalse()
    {
        var result = Validators.ValidatePassword("");
        Assert.False(result.IsValid);
    }
    
    [Fact]
    public void ValidatePassword_AllowsSpecialChars()
    {
        // SECURITY: Passwords should allow any character
        var result = Validators.ValidatePassword("Pass<>\"';&|`$(){}[]");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidatePassword_TooLong_ReturnsFalse()
    {
        var longPassword = new string('a', Validators.MaxPasswordLength + 1);
        var result = Validators.ValidatePassword(longPassword);
        Assert.False(result.IsValid);
    }
    
    // ==================== URL Tests ====================
    
    [Fact]
    public void ValidateUrl_ValidHttps_ReturnsSuccess()
    {
        var result = Validators.ValidateUrl("https://example.com");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateUrl_ValidHttp_ReturnsSuccess()
    {
        var result = Validators.ValidateUrl("http://example.com");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateUrl_Empty_ReturnsSuccess()
    {
        // URL is optional
        var result = Validators.ValidateUrl("");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateUrl_Null_ReturnsSuccess()
    {
        var result = Validators.ValidateUrl(null);
        Assert.True(result.IsValid);
    }
    
    [Theory]
    [InlineData("ftp://example.com")]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:///etc/passwd")]
    public void ValidateUrl_InvalidScheme_ReturnsFalse(string url)
    {
        var result = Validators.ValidateUrl(url);
        Assert.False(result.IsValid);
    }
    
    [Fact]
    public void ValidateUrl_TooLong_ReturnsFalse()
    {
        var longUrl = "https://" + new string('a', Validators.MaxUrlLength);
        var result = Validators.ValidateUrl(longUrl);
        Assert.False(result.IsValid);
    }
    
    // ==================== Notes Tests ====================
    
    [Fact]
    public void ValidateNotes_ValidNotes_ReturnsSuccess()
    {
        var result = Validators.ValidateNotes("This is a note with special chars: äöå!");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateNotes_Empty_ReturnsSuccess()
    {
        var result = Validators.ValidateNotes("");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateNotes_WithNullByte_ReturnsFalse()
    {
        // SECURITY: Null bytes could indicate injection attempt
        var result = Validators.ValidateNotes("Note\0Injection");
        Assert.False(result.IsValid);
    }
    
    [Fact]
    public void ValidateNotes_TooLong_ReturnsFalse()
    {
        var longNotes = new string('a', Validators.MaxNotesLength + 1);
        var result = Validators.ValidateNotes(longNotes);
        Assert.False(result.IsValid);
    }
    
    // ==================== Category Tests ====================
    
    [Fact]
    public void ValidateCategory_ValidCategory_ReturnsSuccess()
    {
        var result = Validators.ValidateCategory("Work");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateCategory_WithSpaces_ReturnsSuccess()
    {
        var result = Validators.ValidateCategory("Social Media");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateCategory_Empty_ReturnsSuccess()
    {
        var result = Validators.ValidateCategory("");
        Assert.True(result.IsValid);
    }
    
    // ==================== Master Password Tests ====================
    
    [Fact]
    public void ValidateMasterPassword_ValidPassword_ReturnsSuccess()
    {
        var result = Validators.ValidateMasterPassword("MySecurePassword123!");
        Assert.True(result.IsValid);
    }
    
    [Fact]
    public void ValidateMasterPassword_TooShort_ReturnsFalse()
    {
        var result = Validators.ValidateMasterPassword("Short1!");
        Assert.False(result.IsValid);
        Assert.Contains("at least", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void ValidateMasterPassword_TooLong_ReturnsFalse()
    {
        var longPassword = new string('a', Validators.MaxMasterPasswordLength + 1);
        var result = Validators.ValidateMasterPassword(longPassword);
        Assert.False(result.IsValid);
    }
    
    // ==================== Password Strength Tests ====================
    
    [Fact]
    public void CheckPasswordStrength_WeakPassword_ReturnsLowScore()
    {
        var strength = Validators.CheckMasterPasswordStrength("password");
        Assert.True(strength.Score < 3);
        Assert.True(strength.Recommendations.Count > 0);
    }
    
    [Fact]
    public void CheckPasswordStrength_StrongPassword_ReturnsHighScore()
    {
        var strength = Validators.CheckMasterPasswordStrength("MyV3ryStr0ng&SecureP@ss!");
        Assert.True(strength.Score >= 5);
        Assert.Equal(StrengthLevel.VeryStrong, strength.Level);
    }
    
    // ==================== Entry Validation Tests ====================
    
    [Fact]
    public void ValidateEntry_AllValid_ReturnsNoErrors()
    {
        var errors = Validators.ValidateEntry(
            "GitHub",
            "user@example.com",
            "SecurePassword123!",
            "https://github.com",
            "My notes",
            "Work");
        
        Assert.Empty(errors);
    }
    
    [Fact]
    public void ValidateEntry_MultipleInvalid_ReturnsAllErrors()
    {
        var errors = Validators.ValidateEntry(
            "",  // Invalid
            "",  // Invalid
            "",  // Invalid
            "invalid-url",  // Invalid
            null,
            null);
        
        Assert.True(errors.Count >= 3);
    }
}

/// <summary>
/// Tests for database operations.
/// 
/// SECURITY: Verifies parameterized queries work correctly
/// to prevent CWE-89 (SQL Injection).
/// </summary>
public class DbManagerTests : IDisposable
{
    private readonly string _testDbPath;
    private readonly DbManager _dbManager;
    
    public DbManagerTests()
    {
        _testDbPath = Path.Combine(Path.GetTempPath(), $"test_vault_{Guid.NewGuid()}.db");
        _dbManager = new DbManager(_testDbPath);
    }
    
    public void Dispose()
    {
        _dbManager.Dispose();
        if (File.Exists(_testDbPath))
        {
            File.Delete(_testDbPath);
        }
    }
    
    [Fact]
    public async Task InitializeSchema_CreatesDatabase()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        Assert.True(File.Exists(_testDbPath));
    }
    
    [Fact]
    public async Task SaveMetadata_LoadMetadata_RoundTrip()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        var salt = new byte[32];
        var hash = new byte[32];
        Random.Shared.NextBytes(salt);
        Random.Shared.NextBytes(hash);
        
        var metadata = new VaultMetadata
        {
            Salt = salt,
            VerificationHash = hash,
            CreatedAt = DateTime.UtcNow,
            LastAccessedAt = DateTime.UtcNow,
            SchemaVersion = 1
        };
        
        await _dbManager.SaveMetadataAsync(metadata);
        var loaded = await _dbManager.LoadMetadataAsync();
        
        Assert.NotNull(loaded);
        Assert.Equal(salt, loaded.Salt);
        Assert.Equal(hash, loaded.VerificationHash);
    }
    
    [Fact]
    public async Task InsertEntry_GetEntry_RoundTrip()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        var encryptedEntry = new EncryptedPasswordEntry
        {
            EncryptedServiceName = [1, 2, 3, 4],
            EncryptedUsername = [5, 6, 7, 8],
            EncryptedPassword = [9, 10, 11, 12],
            CreatedAt = DateTime.UtcNow,
            ModifiedAt = DateTime.UtcNow,
            IsFavorite = true
        };
        
        var id = await _dbManager.InsertEntryAsync(encryptedEntry);
        Assert.True(id > 0);
        
        var loaded = await _dbManager.GetEntryByIdAsync(id);
        Assert.NotNull(loaded);
        Assert.Equal(encryptedEntry.EncryptedServiceName, loaded.EncryptedServiceName);
        Assert.True(loaded.IsFavorite);
    }
    
    [Fact]
    public async Task DeleteEntry_RemovesFromDatabase()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        var entry = new EncryptedPasswordEntry
        {
            EncryptedServiceName = [1, 2, 3],
            EncryptedUsername = [4, 5, 6],
            EncryptedPassword = [7, 8, 9],
            CreatedAt = DateTime.UtcNow,
            ModifiedAt = DateTime.UtcNow
        };
        
        var id = await _dbManager.InsertEntryAsync(entry);
        await _dbManager.DeleteEntryAsync(id);
        
        var loaded = await _dbManager.GetEntryByIdAsync(id);
        Assert.Null(loaded);
    }
    
    [Fact]
    public async Task GetAllEntries_ReturnsAllEntries()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        for (int i = 0; i < 3; i++)
        {
            await _dbManager.InsertEntryAsync(new EncryptedPasswordEntry
            {
                EncryptedServiceName = [1],
                EncryptedUsername = [2],
                EncryptedPassword = [3],
                CreatedAt = DateTime.UtcNow,
                ModifiedAt = DateTime.UtcNow
            });
        }
        
        var entries = await _dbManager.GetAllEntriesAsync();
        Assert.Equal(3, entries.Count);
    }
    
    [Fact]
    public async Task GetEntryCount_ReturnsCorrectCount()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        Assert.Equal(0, await _dbManager.GetEntryCountAsync());
        
        await _dbManager.InsertEntryAsync(new EncryptedPasswordEntry
        {
            EncryptedServiceName = [1],
            EncryptedUsername = [2],
            EncryptedPassword = [3],
            CreatedAt = DateTime.UtcNow,
            ModifiedAt = DateTime.UtcNow
        });
        
        Assert.Equal(1, await _dbManager.GetEntryCountAsync());
    }
    
    [Fact]
    public async Task UpdateEntry_ModifiesExisting()
    {
        await _dbManager.OpenAsync();
        await _dbManager.InitializeSchemaAsync();
        
        var entry = new EncryptedPasswordEntry
        {
            EncryptedServiceName = [1, 2, 3],
            EncryptedUsername = [4, 5, 6],
            EncryptedPassword = [7, 8, 9],
            CreatedAt = DateTime.UtcNow,
            ModifiedAt = DateTime.UtcNow,
            IsFavorite = false
        };
        
        var id = await _dbManager.InsertEntryAsync(entry);
        
        entry.Id = id;
        entry.IsFavorite = true;
        entry.EncryptedServiceName = [10, 11, 12];
        
        await _dbManager.UpdateEntryAsync(entry);
        
        var loaded = await _dbManager.GetEntryByIdAsync(id);
        Assert.NotNull(loaded);
        Assert.True(loaded.IsFavorite);
        Assert.Equal([10, 11, 12], loaded.EncryptedServiceName);
    }
}

/// <summary>
/// Integration tests for VaultService.
/// 
/// SECURITY: Verifies end-to-end encryption and storage works correctly.
/// </summary>
public class VaultServiceTests : IDisposable
{
    private readonly string _testVaultPath;
    private const string ValidMasterPassword = "MySecurePassword123!";
    
    public VaultServiceTests()
    {
        _testVaultPath = Path.Combine(Path.GetTempPath(), $"test_vault_{Guid.NewGuid()}.db");
    }
    
    public void Dispose()
    {
        if (File.Exists(_testVaultPath))
        {
            File.Delete(_testVaultPath);
        }
    }
    
    [Fact]
    public async Task CreateVault_CreatesFile()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        Assert.True(vault.VaultFileExists());
        Assert.True(vault.IsUnlocked);
    }
    
    [Fact]
    public async Task CreateVault_WeakPassword_ThrowsException()
    {
        using var vault = new VaultService(_testVaultPath);
        
        await Assert.ThrowsAsync<ArgumentException>(
            () => vault.CreateVaultAsync("short"));
    }
    
    [Fact]
    public async Task UnlockVault_CorrectPassword_ReturnsTrue()
    {
        // Create vault
        using (var vault = new VaultService(_testVaultPath))
        {
            await vault.CreateVaultAsync(ValidMasterPassword);
        }
        
        // Unlock vault
        using var vault2 = new VaultService(_testVaultPath);
        var result = await vault2.UnlockVaultAsync(ValidMasterPassword);
        
        Assert.True(result);
        Assert.True(vault2.IsUnlocked);
    }
    
    [Fact]
    public async Task UnlockVault_WrongPassword_ReturnsFalse()
    {
        // Create vault
        using (var vault = new VaultService(_testVaultPath))
        {
            await vault.CreateVaultAsync(ValidMasterPassword);
        }
        
        // Try to unlock with wrong password
        using var vault2 = new VaultService(_testVaultPath);
        var result = await vault2.UnlockVaultAsync("WrongPassword123!");
        
        Assert.False(result);
        Assert.False(vault2.IsUnlocked);
    }
    
    [Fact]
    public async Task Lock_ClearsEncryptionKey()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        vault.Lock();
        
        Assert.False(vault.IsUnlocked);
    }
    
    [Fact]
    public async Task AddEntry_GetEntry_RoundTrip()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        var entry = new PasswordEntry
        {
            ServiceName = "GitHub",
            Username = "user@example.com",
            Password = "SecurePassword123!"
        };
        
        var id = await vault.AddEntryAsync(entry);
        Assert.True(id > 0);
        
        var loaded = await vault.GetEntryAsync(id);
        Assert.NotNull(loaded);
        Assert.Equal("GitHub", loaded.ServiceName);
        Assert.Equal("user@example.com", loaded.Username);
        Assert.Equal("SecurePassword123!", loaded.Password);
    }
    
    [Fact]
    public async Task AddEntry_InvalidData_ThrowsException()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        var entry = new PasswordEntry
        {
            ServiceName = "",  // Invalid
            Username = "user",
            Password = "pass"
        };
        
        await Assert.ThrowsAsync<ArgumentException>(
            () => vault.AddEntryAsync(entry));
    }
    
    [Fact]
    public async Task GetAllEntries_ReturnsDecryptedEntries()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        await vault.AddEntryAsync(new PasswordEntry
        {
            ServiceName = "Service1",
            Username = "user1",
            Password = "pass1"
        });
        
        await vault.AddEntryAsync(new PasswordEntry
        {
            ServiceName = "Service2",
            Username = "user2",
            Password = "pass2"
        });
        
        var entries = await vault.GetAllEntriesAsync();
        Assert.Equal(2, entries.Count);
    }
    
    [Fact]
    public async Task UpdateEntry_ModifiesData()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        var entry = new PasswordEntry
        {
            ServiceName = "GitHub",
            Username = "user",
            Password = "oldpassword"
        };
        
        var id = await vault.AddEntryAsync(entry);
        
        entry.Id = id;
        entry.Password = "newpassword";
        
        await vault.UpdateEntryAsync(entry);
        
        var loaded = await vault.GetEntryAsync(id);
        Assert.Equal("newpassword", loaded!.Password);
    }
    
    [Fact]
    public async Task DeleteEntry_RemovesEntry()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        var id = await vault.AddEntryAsync(new PasswordEntry
        {
            ServiceName = "GitHub",
            Username = "user",
            Password = "pass"
        });
        
        await vault.DeleteEntryAsync(id);
        
        var loaded = await vault.GetEntryAsync(id);
        Assert.Null(loaded);
    }
    
    [Fact]
    public async Task ChangeMasterPassword_ReEncryptsAllEntries()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        
        // Add an entry
        await vault.AddEntryAsync(new PasswordEntry
        {
            ServiceName = "GitHub",
            Username = "user",
            Password = "password123"
        });
        
        // Change master password
        const string newPassword = "NewSecurePassword456!";
        await vault.ChangeMasterPasswordAsync(ValidMasterPassword, newPassword);
        
        vault.Lock();
        
        // Unlock with new password
        var result = await vault.UnlockVaultAsync(newPassword);
        Assert.True(result);
        
        // Verify entry is still accessible
        var entries = await vault.GetAllEntriesAsync();
        Assert.Single(entries);
        Assert.Equal("password123", entries[0].Password);
    }
    
    [Fact]
    public async Task OperationOnLockedVault_ThrowsException()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(ValidMasterPassword);
        vault.Lock();
        
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => vault.AddEntryAsync(new PasswordEntry
            {
                ServiceName = "Test",
                Username = "test",
                Password = "test"
            }));
    }
}
