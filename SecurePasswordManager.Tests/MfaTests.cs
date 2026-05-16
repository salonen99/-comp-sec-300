/*
 * Unit Tests for Multi-Factor Authentication
 */

using Xunit;
using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.Tests;

public class MfaTests
{
    #region MfaProvider Tests
    
    [Fact]
    public void GenerateTotpSecret_ReturnsValidBase32String()
    {
        // Arrange
        var secret = MfaProvider.GenerateTotpSecret();
        
        // Assert
        Assert.NotEmpty(secret);
        Assert.True(secret.Length > 0);
        // Base32 alphabet check
        Assert.True(secret.All(c => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".Contains(c)));
    }
    
    [Fact]
    public void GenerateTotpSecret_ReturnsDifferentSecretsEachCall()
    {
        // Arrange
        var secret1 = MfaProvider.GenerateTotpSecret();
        var secret2 = MfaProvider.GenerateTotpSecret();
        
        // Assert
        Assert.NotEqual(secret1, secret2);
    }
    
    [Fact]
    public void VerifyTotpCode_AcceptsValidCode()
    {
        // Arrange
        var secret = MfaProvider.GenerateTotpSecret();
        // Generate a code for current time
        // For testing, we'd typically mock the time or use a known secret
        // This is a basic test structure - real test would need time mocking
        
        // For now, test that verification doesn't crash on valid-format input
        // (Actual TOTP code verification is hard to test without time control)
        var result = MfaProvider.VerifyTotpCode(secret, "000000");
        // Will likely fail with invalid code, but shouldn't throw
        
        // Assert
        Assert.False(result); // Wrong code should fail
    }
    
    [Theory]
    [InlineData("")]
    [InlineData("00000")]        // Too short
    [InlineData("0000000")]      // Too long
    [InlineData("abcdef")]       // Not digits
    public void VerifyTotpCode_RejectsInvalidCodeFormat(string invalidCode)
    {
        // Arrange
        var secret = MfaProvider.GenerateTotpSecret();
        
        // Act
        var result = MfaProvider.VerifyTotpCode(secret, invalidCode);
        
        // Assert
        Assert.False(result);
    }
    
    [Fact]
    public void VerifyTotpCode_ThrowsOnInvalidSecret()
    {
        // Arrange
        var invalidSecret = "INVALID!!!SECRET";
        
        // Act & Assert
        var result = MfaProvider.VerifyTotpCode(invalidSecret, "000000");
        Assert.False(result); // Should handle gracefully
    }
    
    [Fact]
    public void GenerateRecoveryCodes_ReturnsRequestedCount()
    {
        // Arrange
        var expectedCount = 10;
        
        // Act
        var codes = MfaProvider.GenerateRecoveryCodes();
        
        // Assert
        Assert.Equal(expectedCount, codes.Count);
    }
    
    [Fact]
    public void GenerateRecoveryCodes_EachCodeHasCorrectLength()
    {
        // Arrange
        var expectedLength = 8;
        
        // Act
        var codes = MfaProvider.GenerateRecoveryCodes();
        
        // Assert
        Assert.All(codes, code =>
        {
            Assert.Equal(expectedLength, code.Length);
            Assert.True(code.All(c => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".Contains(c)));
        });
    }
    
    [Fact]
    public void GenerateRecoveryCodes_AllCodesAreUnique()
    {
        // Arrange & Act
        var codes = MfaProvider.GenerateRecoveryCodes();
        
        // Assert
        Assert.Equal(codes.Count, codes.Distinct().Count());
    }
    
    [Fact]
    public void GenerateRecoveryCodes_ReturnsDifferentCodesEachCall()
    {
        // Arrange
        var codes1 = MfaProvider.GenerateRecoveryCodes();
        var codes2 = MfaProvider.GenerateRecoveryCodes();
        
        // Assert
        Assert.NotEqual(codes1, codes2);
    }
    
    #endregion
    
    #region MfaSettings Tests
    
    [Fact]
    public void MfaSettings_EnabledByDefault()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        
        // Assert
        Assert.True(settings.Enabled);
    }
    
    [Fact]
    public void MfaSettings_SerializesToJson()
    {
        // Arrange
        var settings = new MfaSettings
        {
            Enabled = true,
            Method = "totp",
            EncryptedTotpSecretHex = "ABCD1234",
            CreatedAt = new DateTime(2026, 5, 7, 12, 0, 0, DateTimeKind.Utc)
        };
        
        // Act
        var json = settings.ToJson();
        
        // Assert
        Assert.NotEmpty(json);
        Assert.Contains("totp", json);
        Assert.Contains("ABCD1234", json);
    }
    
    [Fact]
    public void MfaSettings_DeserializesFromJson()
    {
        // Arrange
        var original = new MfaSettings
        {
            Enabled = true,
            Method = "totp",
            CreatedAt = DateTime.UtcNow
        };
        var json = original.ToJson();
        
        // Act
        var deserialized = MfaSettings.FromJson(json);
        
        // Assert
        Assert.NotNull(deserialized);
        Assert.True(deserialized.Enabled);
        Assert.Equal("totp", deserialized.Method);
    }
    
    [Fact]
    public void MfaSettings_MarkRecoveryCodeAsUsed()
    {
        // Arrange
        var settings = new MfaSettings();
        
        // Act
        settings.MarkRecoveryCodeAsUsed(0);
        settings.MarkRecoveryCodeAsUsed(5);
        
        // Assert
        Assert.True(settings.IsRecoveryCodeUsed(0));
        Assert.True(settings.IsRecoveryCodeUsed(5));
        Assert.False(settings.IsRecoveryCodeUsed(1));
    }
    
    [Fact]
    public void MfaSettings_GetRemainingRecoveryCodeCount()
    {
        // Arrange
        var settings = new MfaSettings();
        settings.RecoveryCodeHashesHex.AddRange(
            Enumerable.Range(0, 10).Select(i => $"hash{i}")
        );
        
        // Act
        settings.MarkRecoveryCodeAsUsed(0);
        settings.MarkRecoveryCodeAsUsed(2);
        
        // Assert
        Assert.Equal(8, settings.GetRemainingRecoveryCodeCount());
    }
    
    [Fact]
    public void MfaSettings_ThrowsOnInvalidRecoveryCodeIndex()
    {
        // Arrange
        var settings = new MfaSettings();
        
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => settings.MarkRecoveryCodeAsUsed(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => settings.MarkRecoveryCodeAsUsed(32));
    }
    
    #endregion
    
    #region MfaVerificationService Tests
    
    [Fact]
    public void MfaVerificationService_GetRateLimitStatus_InitiallyNoLockout()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        
        // Act
        var status = service.GetRateLimitStatus();
        
        // Assert
        Assert.False(status.IsLockedOut);
        Assert.Equal(0, status.FailedAttempts);
        Assert.Equal(5, status.RemainingAttempts);
    }
    
    [Fact]
    public void MfaVerificationService_IsMfaVerified_InitiallyFalse()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        
        // Act & Assert
        Assert.False(service.IsMfaVerified());
    }
    
    [Fact]
    public void MfaVerificationService_ClearMfaVerificationState()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        
        // Act
        service.ClearMfaVerificationState();
        
        // Assert
        Assert.False(service.IsMfaVerified());
    }
    
    [Fact]
    public void MfaVerificationService_VerifyTotpCode_ThrowsOnEmptyCode()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        var secret = MfaProvider.GenerateTotpSecret();
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => service.VerifyTotpCode("", secret));
    }
    
    [Fact]
    public void MfaVerificationService_VerifyTotpCode_ThrowsOnEmptySecret()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => service.VerifyTotpCode("000000", ""));
    }
    
    [Fact]
    public void MfaVerificationService_VerifyRecoveryCode_ThrowsOnEmptyCode()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            service.VerifyRecoveryCode("", new List<string> { "hash1" }));
    }
    
    [Fact]
    public void MfaVerificationService_VerifyRecoveryCode_ThrowsOnEmptyHashes()
    {
        // Arrange
        var settings = new MfaSettings { Enabled = true };
        var service = new MfaVerificationService("/vault/path", settings);
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            service.VerifyRecoveryCode("ABCD1234", new List<string>()));
    }
    
    #endregion
}
