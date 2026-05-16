/*
 * Unit Tests for Cryptographic Modules
 * 
 * SECURITY TESTING:
 * These tests verify that cryptographic operations work correctly
 * and securely. Tests cover:
 * - Key derivation with Argon2id
 * - AES-256-GCM encryption/decryption
 * - Secure random generation
 * - Input validation
 * - Error handling
 */

using System.Security.Cryptography;
using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Utils;
using Xunit;

namespace SecurePasswordManager.Tests;

public class KeyDerivationTests : IDisposable
{
    private readonly KeyDerivation _kdf = new();
    private readonly string _validPassword = "SecureP@ssw0rd123"; // 16+ chars with complexity
    private readonly byte[] _salt;
    
    public KeyDerivationTests()
    {
        _salt = KeyDerivation.GenerateSalt();
    }
    
    // ==================== Salt Generation Tests ====================
    
    [Fact]
    public void GenerateSalt_ReturnsCorrectLength()
    {
        // SECURITY TEST: Salt must be exactly 32 bytes
        byte[] salt = KeyDerivation.GenerateSalt();
        Assert.Equal(32, salt.Length);
    }
    
    [Fact]
    public void GenerateSalt_GeneratesUniqueSalts()
    {
        // SECURITY TEST: Each salt must be unique (high probability)
        var salts = new HashSet<string>();
        
        for (int i = 0; i < 100; i++)
        {
            byte[] salt = KeyDerivation.GenerateSalt();
            salts.Add(Convert.ToBase64String(salt));
        }
        
        Assert.Equal(100, salts.Count);
    }
    
    // ==================== Key Derivation Tests ====================
    
    [Fact]
    public void DeriveKey_ReturnsCorrectLength()
    {
        // SECURITY TEST: Derived key must be exactly 32 bytes (256 bits)
        byte[] key = _kdf.DeriveKey(_validPassword, _salt);
        Assert.Equal(32, key.Length);
    }
    
    [Fact]
    public void DeriveKey_IsDeterministic()
    {
        // SECURITY TEST: Same password + salt must produce same key
        byte[] key1 = _kdf.DeriveKey(_validPassword, _salt);
        byte[] key2 = _kdf.DeriveKey(_validPassword, _salt);
        Assert.Equal(key1, key2);
    }
    
    [Fact]
    public void DeriveKey_DifferentSaltProducesDifferentKey()
    {
        // SECURITY TEST: Different salt must produce different key
        byte[] salt1 = KeyDerivation.GenerateSalt();
        byte[] salt2 = KeyDerivation.GenerateSalt();
        
        byte[] key1 = _kdf.DeriveKey(_validPassword, salt1);
        byte[] key2 = _kdf.DeriveKey(_validPassword, salt2);
        
        Assert.NotEqual(key1, key2);
    }
    
    [Fact]
    public void DeriveKey_DifferentPasswordProducesDifferentKey()
    {
        // SECURITY TEST: Different password must produce different key
        byte[] key1 = _kdf.DeriveKey("ValidPassword123", _salt);
        byte[] key2 = _kdf.DeriveKey("DifferentPass123", _salt);
        
        Assert.NotEqual(key1, key2);
    }
    
    // ==================== Input Validation Tests ====================
    
    [Fact]
    public void DeriveKey_RejectsEmptyPassword()
    {
        // SECURITY TEST: Empty password must be rejected
        var ex = Assert.Throws<ArgumentException>(() => 
            _kdf.DeriveKey("", _salt));
        Assert.Contains("empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void DeriveKey_RejectsShortPassword()
    {
        // SECURITY TEST: Password shorter than minimum must be rejected
        var ex = Assert.Throws<ArgumentException>(() => 
            _kdf.DeriveKey("short", _salt));
        Assert.Contains("at least", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void DeriveKey_RejectsInvalidSalt()
    {
        // SECURITY TEST: Invalid salt must be rejected
        var ex = Assert.Throws<ArgumentException>(() => 
            _kdf.DeriveKey(_validPassword, new byte[10]));
        Assert.Contains("32 bytes", ex.Message);
    }
    
    [Fact]
    public void DeriveKey_RejectsNullSalt()
    {
        // SECURITY TEST: Null salt must be rejected
        Assert.Throws<ArgumentException>(() => 
            _kdf.DeriveKey(_validPassword, null!));
    }
    
    // ==================== Verification Hash Tests ====================
    
    [Fact]
    public void VerifyMasterPassword_AcceptsCorrectPassword()
    {
        // SECURITY TEST: Correct password must verify successfully
        byte[] storedHash = _kdf.CreateVerificationHash(_validPassword, _salt);
        
        bool result = _kdf.VerifyMasterPassword(_validPassword, _salt, storedHash);
        
        Assert.True(result);
    }
    
    [Fact]
    public void VerifyMasterPassword_RejectsWrongPassword()
    {
        // SECURITY TEST: Wrong password must fail verification
        byte[] storedHash = _kdf.CreateVerificationHash(_validPassword, _salt);
        
        bool result = _kdf.VerifyMasterPassword("WrongPassword123", _salt, storedHash);
        
        Assert.False(result);
    }
    
    public void Dispose()
    {
        _kdf.Dispose();
    }
}

public class AesGcmEncryptionTests : IDisposable
{
    private readonly byte[] _key;
    private readonly AesGcmEncryption _encryption;
    private readonly byte[] _testData = "This is test data for encryption"u8.ToArray();
    private const string TestString = "Hello, World! 日本語 🔐";
    
    public AesGcmEncryptionTests()
    {
        _key = RandomNumberGenerator.GetBytes(32);
        _encryption = new AesGcmEncryption(_key);
    }
    
    // ==================== Basic Encryption Tests ====================
    
    [Fact]
    public void Encrypt_ReturnsBytes()
    {
        // SECURITY TEST: Encrypt must return bytes
        byte[] ciphertext = _encryption.Encrypt(_testData);
        Assert.NotNull(ciphertext);
        Assert.True(ciphertext.Length > 0);
    }
    
    [Fact]
    public void Decrypt_ReturnsOriginal()
    {
        // SECURITY TEST: Decrypt must return original plaintext
        byte[] ciphertext = _encryption.Encrypt(_testData);
        byte[] plaintext = _encryption.Decrypt(ciphertext);
        
        Assert.Equal(_testData, plaintext);
    }
    
    [Fact]
    public void Encrypt_ProducesDifferentCiphertextFromPlaintext()
    {
        // SECURITY TEST: Ciphertext must be different from plaintext
        byte[] ciphertext = _encryption.Encrypt(_testData);
        Assert.NotEqual(_testData, ciphertext);
    }
    
    // ==================== Nonce Uniqueness Tests ====================
    
    [Fact]
    public void Encrypt_UsesUniqueNonces()
    {
        // SECURITY TEST: Each encryption must use unique nonce
        byte[] ciphertext1 = _encryption.Encrypt(_testData);
        byte[] ciphertext2 = _encryption.Encrypt(_testData);
        
        // Extract nonces (bytes 1-13, after version byte)
        byte[] nonce1 = ciphertext1[1..13];
        byte[] nonce2 = ciphertext2[1..13];
        
        Assert.NotEqual(nonce1, nonce2);
    }
    
    [Fact]
    public void Encrypt_SameDataProducesDifferentCiphertext()
    {
        // SECURITY TEST: Same data must produce different ciphertext (due to nonce)
        byte[] ciphertext1 = _encryption.Encrypt(_testData);
        byte[] ciphertext2 = _encryption.Encrypt(_testData);
        
        Assert.NotEqual(ciphertext1, ciphertext2);
    }
    
    // ==================== Authentication Tests ====================
    
    [Fact]
    public void Decrypt_DetectsTampering()
    {
        // SECURITY TEST: Tampering must be detected (authentication tag)
        byte[] ciphertext = _encryption.Encrypt(_testData);
        
        // Tamper with the ciphertext
        if (ciphertext.Length > 20)
        {
            ciphertext[20] ^= 0xFF; // Flip bits
        }
        
        var ex = Assert.Throws<CryptographicException>(() => 
            _encryption.Decrypt(ciphertext));
        Assert.Contains("tampered", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void Decrypt_RejectsTruncatedCiphertext()
    {
        // SECURITY TEST: Truncated ciphertext must be rejected
        byte[] ciphertext = _encryption.Encrypt(_testData);
        
        Assert.Throws<ArgumentException>(() => 
            _encryption.Decrypt(ciphertext[..10]));
    }
    
    // ==================== Associated Data Tests ====================
    
    [Fact]
    public void Decrypt_RequiresMatchingAad()
    {
        // SECURITY TEST: AAD must match during decryption
        byte[] aad = "additional authenticated data"u8.ToArray();
        byte[] ciphertext = _encryption.Encrypt(_testData, aad);
        
        // Decrypt with correct AAD should work
        byte[] plaintext = _encryption.Decrypt(ciphertext, aad);
        Assert.Equal(_testData, plaintext);
        
        // Decrypt with wrong AAD should fail
        Assert.Throws<CryptographicException>(() => 
            _encryption.Decrypt(ciphertext, "wrong aad"u8.ToArray()));
    }
    
    // ==================== String Convenience Methods ====================
    
    [Fact]
    public void EncryptString_HandlesUtf8()
    {
        // SECURITY TEST: String encryption must handle UTF-8
        byte[] ciphertext = _encryption.EncryptString(TestString);
        string plaintext = _encryption.DecryptString(ciphertext);
        
        Assert.Equal(TestString, plaintext);
    }
    
    // ==================== Key Validation Tests ====================
    
    [Fact]
    public void Constructor_RejectsInvalidKeyLength()
    {
        // SECURITY TEST: Keys must be exactly 32 bytes
        var ex = Assert.Throws<ArgumentException>(() => 
            new AesGcmEncryption(new byte[16]));
        Assert.Contains("32 bytes", ex.Message);
    }
    
    [Fact]
    public void Constructor_RejectsNullKey()
    {
        // SECURITY TEST: Null key must be rejected
        Assert.Throws<ArgumentException>(() => 
            new AesGcmEncryption(null!));
    }
    
    public void Dispose()
    {
        _encryption.Dispose();
    }
}

public class SecureRandomTests
{
    private readonly SecureRandom _generator = new();
    
    // ==================== Password Generation Tests ====================
    
    [Fact]
    public void GeneratePassword_ReturnsCorrectLength()
    {
        // SECURITY TEST: Generated password must have correct length
        string password = _generator.GeneratePassword(length: 20);
        Assert.Equal(20, password.Length);
    }
    
    [Fact]
    public void GeneratePassword_ContainsRequiredTypes()
    {
        // SECURITY TEST: Password must contain all required character types
        string password = _generator.GeneratePassword(
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true);
        
        Assert.Contains(password, c => char.IsUpper(c));
        Assert.Contains(password, c => char.IsLower(c));
        Assert.Contains(password, c => char.IsDigit(c));
        Assert.Contains(password, c => !char.IsLetterOrDigit(c));
    }
    
    [Fact]
    public void GeneratePassword_GeneratesUniquePasswords()
    {
        // SECURITY TEST: Generated passwords must be unique
        var passwords = new HashSet<string>();
        
        for (int i = 0; i < 100; i++)
        {
            passwords.Add(_generator.GeneratePassword());
        }
        
        Assert.Equal(100, passwords.Count);
    }
    
    [Fact]
    public void GeneratePassword_ExcludesAmbiguousCharacters()
    {
        // SECURITY TEST: Ambiguous characters can be excluded
        const string ambiguous = "0O1lI|";
        
        for (int i = 0; i < 20; i++)
        {
            string password = _generator.GeneratePassword(length: 50, excludeAmbiguous: true);
            
            foreach (char c in ambiguous)
            {
                Assert.DoesNotContain(c.ToString(), password);
            }
        }
    }
    
    // ==================== Minimum Requirements Tests ====================
    
    [Fact]
    public void GeneratePassword_RejectsShortPassword()
    {
        // SECURITY TEST: Too short passwords must be rejected
        var ex = Assert.Throws<ArgumentException>(() => 
            _generator.GeneratePassword(length: 5));
        Assert.Contains("at least", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void GeneratePassword_RejectsLowEntropy()
    {
        // SECURITY TEST: Low entropy configurations must be rejected
        // Use a custom policy with lower min length to test entropy check
        var lowPolicy = new PasswordPolicy { MinLength = 8, MinEntropyBits = 60.0 };
        var generator = new SecureRandom(lowPolicy);
        
        var ex = Assert.Throws<ArgumentException>(() =>
            generator.GeneratePassword(
                length: 8,
                uppercase: false,
                lowercase: true,
                digits: false,
                symbols: false));
        
        Assert.Contains("entropy", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    // ==================== Token Generation Tests ====================
    
    [Fact]
    public void GenerateToken_ReturnsCorrectLength()
    {
        // SECURITY TEST: Token must have correct length
        string token = SecureRandom.GenerateToken(32);
        Assert.Equal(32, token.Length);
    }
    
    [Fact]
    public void GenerateToken_GeneratesUniqueTokens()
    {
        // SECURITY TEST: Generated tokens must be unique
        var tokens = new HashSet<string>();
        
        for (int i = 0; i < 100; i++)
        {
            tokens.Add(SecureRandom.GenerateToken());
        }
        
        Assert.Equal(100, tokens.Count);
    }
    
    [Fact]
    public void GenerateToken_ReturnsHexadecimal()
    {
        // SECURITY TEST: Token must be hexadecimal
        string token = SecureRandom.GenerateToken();
        Assert.All(token, c => Assert.True(
            char.IsDigit(c) || (c >= 'a' && c <= 'f'),
            $"Character '{c}' is not valid hex"));
    }
    
    // ==================== Passphrase Tests ====================
    
    [Fact]
    public void GeneratePassphrase_ReturnsCorrectWordCount()
    {
        // SECURITY TEST: Passphrase must have correct word count
        string passphrase = _generator.GeneratePassphrase(wordCount: 5);
        string[] words = passphrase.Split('-');
        
        Assert.Equal(5, words.Length);
    }
    
    [Fact]
    public void GeneratePassphrase_RejectsLessThanFourWords()
    {
        // SECURITY TEST: Passphrase must have minimum 4 words
        var ex = Assert.Throws<ArgumentException>(() => 
            _generator.GeneratePassphrase(wordCount: 2));
        Assert.Contains("at least 4", ex.Message);
    }
}

public class EncryptedFieldTests : IDisposable
{
    private readonly byte[] _key;
    private readonly AesGcmEncryption _encryption;
    private readonly EncryptedField _field;
    
    public EncryptedFieldTests()
    {
        _key = RandomNumberGenerator.GetBytes(32);
        _encryption = new AesGcmEncryption(_key);
        _field = new EncryptedField(_encryption, "password");
    }
    
    [Fact]
    public void EncryptDecrypt_RoundTrips()
    {
        // SECURITY TEST: Field values must encrypt/decrypt correctly
        const string original = "my_secret_password";
        
        byte[] encrypted = _field.Encrypt(original);
        string decrypted = _field.Decrypt(encrypted);
        
        Assert.Equal(original, decrypted);
    }
    
    [Fact]
    public void DifferentFields_AreIncompatible()
    {
        // SECURITY TEST: Different fields must use different AAD
        using var field1 = new EncryptedField(_encryption, "password");
        using var field2 = new EncryptedField(_encryption, "username");
        
        byte[] encrypted = field1.Encrypt("secret");
        
        // Should fail to decrypt with different field's AAD
        Assert.Throws<CryptographicException>(() => 
            field2.Decrypt(encrypted));
    }
    
    public void Dispose()
    {
        _field.Dispose();
        _encryption.Dispose();
    }
}

public class CryptoIntegrationTests
{
    [Fact]
    public void FullWorkflow_EncryptDecrypt()
    {
        // SECURITY TEST: Full workflow from password to encrypted data
        const string masterPassword = "MySecureMasterPassword123!";
        const string secret = "my_github_password_123";
        
        using var kdf = new KeyDerivation();
        
        // Step 1: Generate salt
        byte[] salt = KeyDerivation.GenerateSalt();
        
        // Step 2: Derive encryption key
        byte[] key = kdf.DeriveKey(masterPassword, salt);
        
        // Step 3: Encrypt some data
        using var encryption = new AesGcmEncryption(key);
        byte[] ciphertext = encryption.EncryptString(secret);
        
        // Step 4: Later, derive key again and decrypt
        using var kdf2 = new KeyDerivation();
        byte[] key2 = kdf2.DeriveKey(masterPassword, salt);
        
        using var encryption2 = new AesGcmEncryption(key2);
        string decrypted = encryption2.DecryptString(ciphertext);
        
        Assert.Equal(secret, decrypted);
    }
    
    [Fact]
    public void WrongPassword_CannotDecrypt()
    {
        // SECURITY TEST: Wrong master password must not decrypt data
        using var kdf = new KeyDerivation();
        byte[] salt = KeyDerivation.GenerateSalt();
        
        // Encrypt with correct password
        byte[] correctKey = kdf.DeriveKey("CorrectPassword123!", salt);
        using var encryption = new AesGcmEncryption(correctKey);
        byte[] ciphertext = encryption.EncryptString("secret data");
        
        // Try to decrypt with wrong password
        byte[] wrongKey = kdf.DeriveKey("WrongPassword12345", salt);
        using var wrongEncryption = new AesGcmEncryption(wrongKey);
        
        Assert.Throws<CryptographicException>(() => 
            wrongEncryption.DecryptString(ciphertext));
    }
}

public class PasswordGeneratorTests
{
    // ==================== Basic Functionality Tests ====================
    
    [Fact]
    public void GeneratePassword_WithDefaultSettings_ReturnsValid32CharPassword()
    {
        // SECURITY TEST: Default password generation should produce 32 character password
        string password = PasswordGenerator.GeneratePassword();
        Assert.Equal(32, password.Length);
        
        // Should contain all character types by default
        Assert.Contains(password, c => char.IsUpper(c));
        Assert.Contains(password, c => char.IsLower(c));
        Assert.Contains(password, c => char.IsDigit(c));
        Assert.Contains(password, c => !char.IsLetterOrDigit(c));
    }
    
    [Fact]
    public void GeneratePassword_WithCustomLength_ReturnsCorrectLength()
    {
        // SECURITY TEST: Custom length should be respected
        int[] lengths = { 16, 32, 64, 128 };
        
        foreach (int length in lengths)
        {
            string password = PasswordGenerator.GeneratePassword(length: length);
            Assert.Equal(length, password.Length);
        }
    }
    
    [Fact]
    public void GeneratePassword_WithUppercaseDisabled_DoesNotContainUppercase()
    {
        // SECURITY TEST: Uppercase can be disabled
        for (int i = 0; i < 20; i++)
        {
            string password = PasswordGenerator.GeneratePassword(
                length: 32,
                uppercase: false,
                lowercase: true,
                digits: true,
                symbols: true);
            
            Assert.DoesNotContain(password, c => char.IsUpper(c));
        }
    }
    
    [Fact]
    public void GeneratePassword_WithLowercaseDisabled_DoesNotContainLowercase()
    {
        // SECURITY TEST: Lowercase can be disabled
        for (int i = 0; i < 20; i++)
        {
            string password = PasswordGenerator.GeneratePassword(
                length: 32,
                uppercase: true,
                lowercase: false,
                digits: true,
                symbols: true);
            
            Assert.DoesNotContain(password, c => char.IsLower(c));
        }
    }
    
    [Fact]
    public void GeneratePassword_WithDigitsDisabled_DoesNotContainDigits()
    {
        // SECURITY TEST: Digits can be disabled
        for (int i = 0; i < 20; i++)
        {
            string password = PasswordGenerator.GeneratePassword(
                length: 32,
                uppercase: true,
                lowercase: true,
                digits: false,
                symbols: true);
            
            Assert.DoesNotContain(password, c => char.IsDigit(c));
        }
    }
    
    [Fact]
    public void GeneratePassword_WithSymbolsDisabled_DoesNotContainSymbols()
    {
        // SECURITY TEST: Symbols can be disabled
        for (int i = 0; i < 20; i++)
        {
            string password = PasswordGenerator.GeneratePassword(
                length: 32,
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: false);
            
            // Check that password doesn't contain common symbol characters
            var symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            Assert.DoesNotContain(password, c => symbolChars.Contains(c));
        }
    }
    
    [Fact]
    public void GeneratePassword_WithAmbiguousExcluded_NoAmbiguousCharacters()
    {
        // SECURITY TEST: Ambiguous characters can be excluded
        const string ambiguous = "0O1lI|";
        
        for (int i = 0; i < 20; i++)
        {
            string password = PasswordGenerator.GeneratePassword(
                length: 50,
                excludeAmbiguous: true);
            
            foreach (char c in ambiguous)
            {
                Assert.DoesNotContain(c.ToString(), password);
            }
        }
    }
    
    // ==================== Validation Tests ====================
    
    [Fact]
    public void GeneratePassword_RejectsShortLength()
    {
        // SECURITY TEST: Password length below minimum should be rejected
        var ex = Assert.Throws<ArgumentException>(() => 
            PasswordGenerator.GeneratePassword(length: 4));
        Assert.Contains("at least 8", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void GeneratePassword_RejectsLongLength()
    {
        // SECURITY TEST: Password length above maximum should be rejected
        var ex = Assert.Throws<ArgumentException>(() => 
            PasswordGenerator.GeneratePassword(length: 300));
        Assert.Contains("not exceed 256", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    [Fact]
    public void GeneratePassword_RejectsNoCharacterTypes()
    {
        // SECURITY TEST: At least one character type must be selected
        var ex = Assert.Throws<ArgumentException>(() => 
            PasswordGenerator.GeneratePassword(
                length: 32,
                uppercase: false,
                lowercase: false,
                digits: false,
                symbols: false));
        Assert.Contains("At least one character type", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
    
    // ==================== Combination Tests ====================
    
    [Fact]
    public void GeneratePassword_WithMultipleDisabled_OnlyContainsAllowedTypes()
    {
        // SECURITY TEST: Password should only contain selected character types
        string password = PasswordGenerator.GeneratePassword(
            length: 32,
            uppercase: true,
            lowercase: false,
            digits: true,
            symbols: false,
            excludeAmbiguous: false);
        
        // Should only contain uppercase and digits
        Assert.All(password, c =>
        {
            Assert.True(char.IsUpper(c) || char.IsDigit(c),
                $"Character '{c}' is neither uppercase nor digit");
        });
    }
    
    [Fact]
    public void GeneratePassword_GeneratesUniquePasswords()
    {
        // SECURITY TEST: Generated passwords should be unique
        var passwords = new HashSet<string>();
        
        for (int i = 0; i < 100; i++)
        {
            passwords.Add(PasswordGenerator.GeneratePassword(length: 32));
        }
        
        Assert.Equal(100, passwords.Count);
    }
}

