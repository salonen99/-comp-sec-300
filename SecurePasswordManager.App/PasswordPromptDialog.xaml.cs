using System.Windows;
using SecurePasswordManager.Core.Utils;

namespace SecurePasswordManager.App;

/// <summary>
/// Dialog for entering master password (used for encrypted export verification).
/// </summary>
public partial class PasswordPromptDialog : Window
{
    private readonly AuthService _authService = new();

    public string Password { get; private set; } = "";
    public string Message { get; set; } = "Enter your password:";

    public PasswordPromptDialog()
    {
        InitializeComponent();
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        var password = PasswordBox.Password;
        
        if (string.IsNullOrEmpty(password))
        {
            ErrorBlock.Text = "Password cannot be empty";
            return;
        }
        
        Password = password;
        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
