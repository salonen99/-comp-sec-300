using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.App;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private VaultService? _vault;
    private readonly AuthService _authService = new AuthService();
    
    public MainWindow()
    {
        InitializeComponent();
    }
    
    private async void OnCreateVault(object sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Password;
        
        if (string.IsNullOrWhiteSpace(password))
        {
            StatusMessage.Text = "Please enter a master password";
            return;
        }
        
        try
        {
            var vaultPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SecurePasswordManager",
                "vault.db");
            
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(vaultPath)!);
            
            _vault = new VaultService(vaultPath);
            await _vault.CreateVaultAsync(password);

            var enableMfa = MessageBox.Show(
                "Do you want to enable Multi-Factor Authentication now?",
                "Enable MFA (Recommended)",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (enableMfa == MessageBoxResult.Yes)
            {
                var setupDialog = new MfaSetupDialog(_vault)
                {
                    Owner = this
                };

                if (setupDialog.ShowDialog() != true)
                {
                    StatusMessage.Text = "Vault created. MFA setup skipped.";
                }
            }
            
            StatusMessage.Text = "[OK] Vault created successfully!";
            PasswordBox.Clear();
            
            // Open vault window
            var vaultWindow = new VaultWindow(_vault);
            vaultWindow.Show();
            Close();
        }
        catch (Exception ex)
        {
            StatusMessage.Text = $"Error: {ex.Message}";
        }
    }
    
    private async void OnUnlockVault(object sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Password;
        
        if (string.IsNullOrWhiteSpace(password))
        {
            StatusMessage.Text = "Please enter your master password";
            return;
        }
        
        try
        {
            var vaultPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SecurePasswordManager",
                "vault.db");
            
            // Phase 3: Check for rate limiting (brute-force protection)
            if (_authService.IsLockedOut(vaultPath))
            {
                var remaining = _authService.GetLockoutTimeRemaining(vaultPath);
                var mins = remaining.Minutes;
                var secs = remaining.Seconds;
                StatusMessage.Text = $"[LOCKED] Vault locked due to failed attempts. Try again in {mins}m {secs}s";
                return;
            }
            
            _vault = new VaultService(vaultPath);
            var success = await _vault.UnlockVaultAsync(password);
            var finalUnlockSuccess = success;
            
            if (success)
            {
                var mfaSettings = _vault.GetMfaSettings();
                if (mfaSettings != null && mfaSettings.Enabled)
                {
                    var mfaDialog = new MfaPromptDialog(_vault)
                    {
                        Owner = this
                    };

                    var mfaResult = mfaDialog.ShowDialog();
                    if (mfaResult != true)
                    {
                        _vault.Lock();
                        finalUnlockSuccess = false;
                        _authService.ValidateUnlockAttempt(vaultPath, finalUnlockSuccess);
                        StatusMessage.Text = "[ERROR] MFA verification failed. Vault remains locked.";
                        return;
                    }
                }

                _authService.ValidateUnlockAttempt(vaultPath, finalUnlockSuccess);

                StatusMessage.Text = "[OK] Vault unlocked successfully!";
                PasswordBox.Clear();
                
                // Open vault window
                var vaultWindow = new VaultWindow(_vault);
                vaultWindow.Show();
                Close();
            }
            else
            {
                _authService.ValidateUnlockAttempt(vaultPath, finalUnlockSuccess);
                var failedCount = _authService.GetFailedAttemptCount(vaultPath);
                var remaining = 5 - failedCount;
                
                if (remaining > 0)
                {
                    StatusMessage.Text = $"[ERROR] Incorrect master password ({remaining} attempts remaining)";
                }
                else
                {
                    StatusMessage.Text = "[BLOCKED] Too many failed attempts. Vault locked for 5 minutes.";
                }
            }
        }
        catch (SecurePasswordManager.Core.Utils.SecurityException ex)
        {
            // Phase 4: Vault file is already open in another instance
            StatusMessage.Text = $"[ERROR] {ex.Message}";
        }
        catch (FileNotFoundException)
        {
            StatusMessage.Text = "No vault found. Please create a new one.";
        }
        catch (Exception ex)
        {
            StatusMessage.Text = $"Error: {ex.Message}";
        }
    }
}