using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Media.Imaging;
using QRCoder;
using SecurePasswordManager.Core.Crypto;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.App;

public partial class MfaSetupDialog : Window
{
    private readonly VaultService _vault;
    private readonly string _totpSecretBase32;
    private readonly List<string> _recoveryCodes;

    public MfaSetupDialog(VaultService vault)
    {
        InitializeComponent();
        _vault = vault;

        _totpSecretBase32 = MfaProvider.GenerateTotpSecret();
        _recoveryCodes = MfaProvider.GenerateRecoveryCodes();

        SecretTextBox.Text = _totpSecretBase32;
        RecoveryCodesTextBox.Text = string.Join(Environment.NewLine, _recoveryCodes.Select((c, i) => $"{i + 1:D2}. {c}"));
        RenderQrCode();
    }

    public IReadOnlyList<string> RecoveryCodes => _recoveryCodes;

    private void RenderQrCode()
    {
        var account = Environment.UserName;
        var issuer = "SecurePasswordManager";
        var uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?secret={_totpSecretBase32}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30";

        using var qrGenerator = new QRCodeGenerator();
        using var qrData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        var pngQr = new PngByteQRCode(qrData);
        var pngBytes = pngQr.GetGraphic(8);

        var image = new BitmapImage();
        using var ms = new MemoryStream(pngBytes);
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = ms;
        image.EndInit();
        image.Freeze();

        QrCodeImage.Source = image;
    }

    private async void OnEnableMfa(object sender, RoutedEventArgs e)
    {
        try
        {
            ErrorText.Text = string.Empty;
            var code = VerifyCodeBox.Text.Trim();

            if (!MfaProvider.VerifyTotpCode(_totpSecretBase32, code))
            {
                ErrorText.Text = "Invalid verification code.";
                return;
            }

            await _vault.EnableMfaAsync(_totpSecretBase32, _recoveryCodes);
            DialogResult = true;
            Close();
        }
        catch (Exception ex)
        {
            ErrorText.Text = ex.Message;
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
