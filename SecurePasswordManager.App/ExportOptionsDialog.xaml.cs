using System.Windows;

namespace SecurePasswordManager.App;

/// <summary>
/// Dialog for selecting export format and encryption options.
/// </summary>
public partial class ExportOptionsDialog : Window
{
    public bool ExportAsJson { get; private set; }
    public bool EncryptExport { get; private set; }

    public ExportOptionsDialog()
    {
        InitializeComponent();
    }

    private void OnExport(object sender, RoutedEventArgs e)
    {
        ExportAsJson = JsonRadioButton.IsChecked == true;
        EncryptExport = EncryptCheckbox.IsChecked == true;
        
        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
