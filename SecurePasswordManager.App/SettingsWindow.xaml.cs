using System;
using System.Windows;
using SecurePasswordManager.Core.Services;
using SecurePasswordManager.Core.Utils;

namespace SecurePasswordManager.App;

public partial class SettingsWindow : Window
{
    private readonly AppSettings _settings = new AppSettings();
    private readonly VaultService? _vault;

    public SettingsWindow()
        : this(null)
    {
    }

    public SettingsWindow(VaultService? vault)
    {
        InitializeComponent();
        _vault = vault;
        _settings.Load();
        
        // Load timeout setting
        TimeoutBox.Text = _settings.SessionTimeoutMinutes.ToString();
        
        // Load strength enforcement settings
        EnforcePasswordStrengthCheckbox.IsChecked = _settings.EnforcePasswordStrength;
        
        // Set min strength level combo
        var levelIndex = _settings.MinPasswordStrengthLevel switch
        {
            "VeryWeak" => 0,
            "Weak" => 1,
            "Fair" => 2,
            "Good" => 3,
            "Strong" => 4,
            "VeryStrong" => 5,
            _ => 2  // Default to Fair
        };
        MinStrengthLevelCombo.SelectedIndex = levelIndex;
        MinStrengthLevelCombo.IsEnabled = _settings.EnforcePasswordStrength;
        
        // Hook up checkbox change event to enable/disable combo
        EnforcePasswordStrengthCheckbox.Checked += (s, e) => MinStrengthLevelCombo.IsEnabled = true;
        EnforcePasswordStrengthCheckbox.Unchecked += (s, e) => MinStrengthLevelCombo.IsEnabled = false;

        RefreshMfaState();
    }

    private void RefreshMfaState()
    {
        if (_vault == null || !_vault.IsUnlocked)
        {
            MfaStatusText.Text = "Status: Vault unavailable";
            EnableMfaButton.IsEnabled = false;
            DisableMfaButton.IsEnabled = false;
            RegenerateCodesButton.IsEnabled = false;
            return;
        }

        var mfa = _vault.GetMfaSettings();
        var enabled = mfa != null && mfa.Enabled;

        if (!enabled)
        {
            MfaStatusText.Text = "Status: Disabled";
            EnableMfaButton.IsEnabled = true;
            DisableMfaButton.IsEnabled = false;
            RegenerateCodesButton.IsEnabled = false;
            return;
        }

        MfaStatusText.Text = $"Status: Enabled ({mfa!.GetRemainingRecoveryCodeCount()} recovery codes left)";
        EnableMfaButton.IsEnabled = false;
        DisableMfaButton.IsEnabled = true;
        RegenerateCodesButton.IsEnabled = true;
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        if (int.TryParse(TimeoutBox.Text, out var mins) && mins > 0)
        {
            _settings.SessionTimeoutMinutes = mins;
            
            // Save strength enforcement settings
            _settings.EnforcePasswordStrength = EnforcePasswordStrengthCheckbox.IsChecked ?? false;
            _settings.MinPasswordStrengthLevel = GetSelectedStrengthLevel();
            
            _settings.Save();
            DialogResult = true;
            Close();
        }
        else
        {
            MessageBox.Show("Please enter a valid number of minutes.", "Invalid", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnEnableMfa(object sender, RoutedEventArgs e)
    {
        if (_vault == null)
            return;

        var setupDialog = new MfaSetupDialog(_vault)
        {
            Owner = this
        };

        if (setupDialog.ShowDialog() == true)
        {
            MessageBox.Show(
                "MFA enabled. Save your recovery codes in a secure location.",
                "MFA Enabled",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            RefreshMfaState();
        }
    }

    private async void OnDisableMfa(object sender, RoutedEventArgs e)
    {
        if (_vault == null)
            return;

        var result = MessageBox.Show(
            "Disable MFA for this vault? This reduces account security.",
            "Disable MFA",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes)
            return;

        await _vault.DisableMfaAsync();
        RefreshMfaState();
    }

    private void OnRegenerateCodes(object sender, RoutedEventArgs e)
    {
        if (_vault == null)
            return;

        var setupDialog = new MfaSetupDialog(_vault)
        {
            Owner = this
        };

        if (setupDialog.ShowDialog() == true)
        {
            MessageBox.Show(
                "Recovery codes were regenerated. Old recovery codes are no longer valid.",
                "Recovery Codes Regenerated",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            RefreshMfaState();
        }
    }
    
    private string GetSelectedStrengthLevel()
    {
        return MinStrengthLevelCombo.SelectedIndex switch
        {
            0 => "VeryWeak",
            1 => "Weak",
            2 => "Fair",
            3 => "Good",
            4 => "Strong",
            5 => "VeryStrong",
            _ => "Fair"
        };
    }
}
