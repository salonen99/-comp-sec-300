using System;
using System.Threading.Tasks;
using System.Windows;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.App;

public partial class MfaPromptDialog : Window
{
    private readonly VaultService _vault;

    public MfaPromptDialog(VaultService vault)
    {
        InitializeComponent();
        _vault = vault;
    }

    private async void OnVerify(object sender, RoutedEventArgs e)
    {
        try
        {
            ErrorText.Text = string.Empty;

            bool verified;
            if (MfaTabControl.SelectedIndex == 0)
            {
                var code = TotpCodeBox.Text.Trim();
                verified = _vault.VerifyMfaTotpCode(code);
            }
            else
            {
                var code = RecoveryCodeBox.Text.Trim().ToUpperInvariant();
                verified = await _vault.VerifyRecoveryCodeAsync(code);
            }

            if (verified)
            {
                DialogResult = true;
                Close();
                return;
            }

            var status = _vault.GetMfaVerificationService()?.GetRateLimitStatus();
            if (status != null && status.IsLockedOut)
            {
                ErrorText.Text = $"Too many failed attempts. Try again in {status.RemainingLockoutSeconds}s.";
            }
            else if (status != null)
            {
                ErrorText.Text = $"Invalid code. {status.RemainingAttempts} attempt(s) remaining.";
            }
            else
            {
                ErrorText.Text = "Invalid code.";
            }
        }
        catch (InvalidOperationException ex)
        {
            ErrorText.Text = ex.Message;
        }
        catch (Exception ex)
        {
            ErrorText.Text = $"Verification failed: {ex.Message}";
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
