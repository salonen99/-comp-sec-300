using System.Security.Cryptography;
using System.Text;
using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.Tests;

public class MfaIntegrationTests : IDisposable
{
    private readonly string _testVaultPath;
    private const string MasterPassword = "MySecurePassword123!";

    public MfaIntegrationTests()
    {
        _testVaultPath = Path.Combine(Path.GetTempPath(), $"test_mfa_vault_{Guid.NewGuid()}.db");
    }

    public void Dispose()
    {
        if (File.Exists(_testVaultPath))
        {
            File.Delete(_testVaultPath);
        }

        var lockFile = _testVaultPath + ".lock";
        if (File.Exists(lockFile))
        {
            File.Delete(lockFile);
        }
    }

    [Fact]
    public async Task EnableMfa_ThenUnlock_LoadsEnabledSettings()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(MasterPassword);

        var secret = MfaProvider.GenerateTotpSecret();
        var recoveryCodes = MfaProvider.GenerateRecoveryCodes();
        await vault.EnableMfaAsync(secret, recoveryCodes);

        vault.Lock();

        var unlocked = await vault.UnlockVaultAsync(MasterPassword);
        Assert.True(unlocked);

        var settings = vault.GetMfaSettings();
        Assert.NotNull(settings);
        Assert.True(settings!.Enabled);
        Assert.NotNull(vault.GetMfaVerificationService());
    }

    [Fact]
    public async Task VerifyMfaTotpCode_WithCurrentCode_ReturnsTrue()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(MasterPassword);

        var secret = MfaProvider.GenerateTotpSecret();
        var recoveryCodes = MfaProvider.GenerateRecoveryCodes();
        await vault.EnableMfaAsync(secret, recoveryCodes);

        vault.Lock();
        var unlocked = await vault.UnlockVaultAsync(MasterPassword);
        Assert.True(unlocked);

        var code = GenerateCurrentTotpCode(secret);
        var verified = vault.VerifyMfaTotpCode(code);

        Assert.True(verified);
    }

    [Fact]
    public async Task VerifyRecoveryCodeAsync_CodeCanOnlyBeUsedOnce()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(MasterPassword);

        var secret = MfaProvider.GenerateTotpSecret();
        var recoveryCodes = MfaProvider.GenerateRecoveryCodes();
        await vault.EnableMfaAsync(secret, recoveryCodes);

        vault.Lock();
        var unlocked = await vault.UnlockVaultAsync(MasterPassword);
        Assert.True(unlocked);

        var firstUse = await vault.VerifyRecoveryCodeAsync(recoveryCodes[0]);
        var secondUse = await vault.VerifyRecoveryCodeAsync(recoveryCodes[0]);

        Assert.True(firstUse);
        Assert.False(secondUse);

        var settings = vault.GetMfaSettings();
        Assert.NotNull(settings);
        Assert.True(settings!.IsRecoveryCodeUsed(0));
    }

    [Fact]
    public async Task ChangeMasterPassword_PreservesMfaSettings()
    {
        using var vault = new VaultService(_testVaultPath);
        await vault.CreateVaultAsync(MasterPassword);

        var secret = MfaProvider.GenerateTotpSecret();
        var recoveryCodes = MfaProvider.GenerateRecoveryCodes();
        await vault.EnableMfaAsync(secret, recoveryCodes);

        var newPassword = "MyEvenStrongerPassword456!";
        await vault.ChangeMasterPasswordAsync(MasterPassword, newPassword);

        vault.Lock();
        var unlocked = await vault.UnlockVaultAsync(newPassword);

        Assert.True(unlocked);
        var settings = vault.GetMfaSettings();
        Assert.NotNull(settings);
        Assert.True(settings!.Enabled);
        Assert.NotEmpty(settings.RecoveryCodeHashesHex);
        Assert.False(string.IsNullOrEmpty(settings.EncryptedTotpSecretHex));
    }

    private static string GenerateCurrentTotpCode(string secretBase32)
    {
        var secret = DecodeBase32(secretBase32);
        var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var counter = unixTime / 30;

        Span<byte> counterBytes = stackalloc byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counterBytes.ToArray());

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   | (hash[offset + 3] & 0xFF);

        var code = binary % 1_000_000;
        return code.ToString("D6");
    }

    private static byte[] DecodeBase32(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bits = new List<byte>();

        foreach (var c in input.ToUpperInvariant())
        {
            var value = alphabet.IndexOf(c);
            if (value < 0)
                throw new FormatException("Invalid Base32 input.");

            for (int i = 4; i >= 0; i--)
            {
                bits.Add((byte)((value >> i) & 1));
            }
        }

        var bytes = new List<byte>(bits.Count / 8);
        for (int i = 0; i + 7 < bits.Count; i += 8)
        {
            byte b = 0;
            for (int j = 0; j < 8; j++)
            {
                b = (byte)((b << 1) | bits[i + j]);
            }
            bytes.Add(b);
        }

        return bytes.ToArray();
    }
}
