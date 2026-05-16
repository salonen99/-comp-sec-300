using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Utils;

namespace SecurePasswordManager.App;

/// <summary>
/// Password generation settings stored during the session
/// </summary>
internal class PasswordGenerationSettings
{
    public int Length { get; set; } = 32;
    public bool IncludeUppercase { get; set; } = true;
    public bool IncludeLowercase { get; set; } = true;
    public bool IncludeDigits { get; set; } = true;
    public bool IncludeSymbols { get; set; } = true;
    public bool ExcludeAmbiguous { get; set; } = false;
}

public partial class EntryWindow : Window
{
    private PasswordEntry? _currentEntry;
    private PasswordGenerationSettings _passwordSettings = new();
    
    // For new entry
    public EntryWindow()
    {
        InitializeComponent();
        TitleText.Text = "Add New Entry";
        
        // Hook up password strength meter event
        PasswordBox.PasswordChanged += (s, e) => UpdatePasswordStrengthMeter();
        
        // Hook up password generation settings after window is loaded
        Loaded += (s, e) => InitializePasswordGenerationControls();
    }
    
    // For editing existing entry
    public EntryWindow(PasswordEntry entry)
    {
        InitializeComponent();
        _currentEntry = entry;
        TitleText.Text = "Edit Entry";
        
        // Hook up password strength meter event
        PasswordBox.PasswordChanged += (s, e) => UpdatePasswordStrengthMeter();
        
        // Hook up password generation settings after window is loaded
        Loaded += (s, e) => InitializePasswordGenerationControls();
        
        // Populate fields
        ServiceNameBox.Text = entry.ServiceName;
        UsernameBox.Text = entry.Username;
        PasswordBox.Password = entry.Password;
        UrlBox.Text = entry.Url ?? "";
        NotesBox.Text = entry.Notes ?? "";
        if (!string.IsNullOrEmpty(entry.Category))
        {
            SetSelectedCategory(entry.Category);
        }
        
        // Update strength meter for loaded password
        UpdatePasswordStrengthMeter();
    }
    
    public PasswordEntry GetEntry()
    {
        return _currentEntry ?? new PasswordEntry();
    }
    
    private void OnSave(object sender, RoutedEventArgs e)
    {
        // Clear previous errors
        ServiceNameError.Text = "";
        UsernameError.Text = "";
        PasswordError.Text = "";
        
        // Validate inputs
        var errors = Validators.ValidateEntry(
            ServiceNameBox.Text,
            UsernameBox.Text,
            PasswordBox.Password,
            UrlBox.Text,
            NotesBox.Text,
            GetSelectedCategory());
        
        if (errors.Count > 0)
        {
            // Show errors
            foreach (var error in errors)
            {
                if (error.ErrorMessage?.Contains("Service", StringComparison.OrdinalIgnoreCase) == true)
                    ServiceNameError.Text = error.ErrorMessage;
                else if (error.ErrorMessage?.Contains("Username", StringComparison.OrdinalIgnoreCase) == true)
                    UsernameError.Text = error.ErrorMessage;
                else if (error.ErrorMessage?.Contains("Password", StringComparison.OrdinalIgnoreCase) == true)
                    PasswordError.Text = error.ErrorMessage;
            }
            return;
        }
        
        // Phase 3: Check password strength enforcement
        var settings = new AppSettings();
        settings.Load();
        
        if (settings.EnforcePasswordStrength)
        {
            var strength = Validators.CheckMasterPasswordStrength(PasswordBox.Password);
            var minLevel = settings.MinPasswordStrengthLevel switch
            {
                "VeryWeak" => StrengthLevel.VeryWeak,
                "Weak" => StrengthLevel.Weak,
                "Fair" => StrengthLevel.Fair,
                "Good" => StrengthLevel.Good,
                "Strong" => StrengthLevel.Strong,
                "VeryStrong" => StrengthLevel.VeryStrong,
                _ => StrengthLevel.Fair
            };
            
            if (strength.Level < minLevel)
            {
                PasswordError.Text = $"[ERROR] Password too weak. Minimum required: {minLevel}";
                return;
            }
        }
        
        // Create or update entry
        if (_currentEntry == null)
        {
            _currentEntry = new PasswordEntry();
        }
        
        _currentEntry.ServiceName = ServiceNameBox.Text;
        _currentEntry.Username = UsernameBox.Text;
        _currentEntry.Password = PasswordBox.Password;
        _currentEntry.Url = string.IsNullOrEmpty(UrlBox.Text) ? null : UrlBox.Text;
        _currentEntry.Notes = string.IsNullOrWhiteSpace(NotesBox.Text) ? null : NotesBox.Text;
        _currentEntry.Category = GetSelectedCategory();
        _currentEntry.ModifiedAt = DateTime.UtcNow;
        
        if (_currentEntry.CreatedAt == default)
        {
            _currentEntry.CreatedAt = DateTime.UtcNow;
        }
        
        DialogResult = true;
        Close();
    }
    
    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnGeneratePassword(object sender, RoutedEventArgs e)
    {
        try
        {
            // Validate that at least one character type is selected
            if (!_passwordSettings.IncludeUppercase &&
                !_passwordSettings.IncludeLowercase &&
                !_passwordSettings.IncludeDigits &&
                !_passwordSettings.IncludeSymbols)
            {
                PasswordError.Text = "[ERROR] At least one character type must be selected";
                return;
            }

            var generatedPassword = PasswordGenerator.GeneratePassword(
                _passwordSettings.Length,
                _passwordSettings.IncludeUppercase,
                _passwordSettings.IncludeLowercase,
                _passwordSettings.IncludeDigits,
                _passwordSettings.IncludeSymbols,
                _passwordSettings.ExcludeAmbiguous);
            
            PasswordBox.Password = generatedPassword;
            PasswordError.Text = "[OK] Password generated successfully";
            UpdatePasswordStrengthMeter();
        }
        catch (Exception ex)
        {
            PasswordError.Text = $"Error generating password: {ex.Message}";
        }
    }

    private void UpdatePasswordStrengthMeter()
    {
        var password = PasswordBox.Password ?? "";
        
        // Get password strength
        var strength = Validators.CheckMasterPasswordStrength(password);
        
        // Update progress bar value (0-100)
        StrengthProgressBar.Value = strength.Score * (100.0 / 6.0); // Score is 0-6, map to 0-100
        
        // Update progress bar color based on strength level
        StrengthProgressBar.Foreground = strength.Level switch
        {
            StrengthLevel.VeryWeak => new SolidColorBrush(Color.FromArgb(255, 244, 67, 54)),    // Red
            StrengthLevel.Weak => new SolidColorBrush(Color.FromArgb(255, 255, 152, 0)),        // Orange
            StrengthLevel.Fair => new SolidColorBrush(Color.FromArgb(255, 255, 193, 7)),        // Yellow
            StrengthLevel.Good => new SolidColorBrush(Color.FromArgb(255, 139, 195, 74)),       // Light Green
            StrengthLevel.Strong => new SolidColorBrush(Color.FromArgb(255, 76, 175, 80)),      // Green
            StrengthLevel.VeryStrong => new SolidColorBrush(Color.FromArgb(255, 56, 142, 60)),  // Dark Green
            _ => new SolidColorBrush(Color.FromArgb(255, 244, 67, 54))
        };
        
        // Update badge text and color
        StrengthBadge.Text = $"[{strength.Level}]";
        StrengthBadge.Foreground = StrengthProgressBar.Foreground;
        
        // Update recommendations
        if (strength.Recommendations.Count > 0)
        {
            StrengthRecommendations.Text = "• " + string.Join(Environment.NewLine + "• ", strength.Recommendations);
        }
        else
        {
            StrengthRecommendations.Text = "Strong password";
        }
    }

    private string? GetSelectedCategory()
    {
        return CategoryBox.SelectedItem switch
        {
            ComboBoxItem item => item.Content?.ToString(),
            string text => text,
            _ => null
        };
    }

    private void InitializePasswordGenerationControls()
    {
        // Find controls dynamically since they're defined in XAML
        var passwordLengthSlider = FindName("PasswordLengthSlider") as Slider;
        var passwordLengthValue = FindName("PasswordLengthValue") as TextBlock;
        var includeUppercaseCheckBox = FindName("IncludeUppercaseCheckBox") as CheckBox;
        var includeLowercaseCheckBox = FindName("IncludeLowercaseCheckBox") as CheckBox;
        var includeDigitsCheckBox = FindName("IncludeDigitsCheckBox") as CheckBox;
        var includeSymbolsCheckBox = FindName("IncludeSymbolsCheckBox") as CheckBox;
        var excludeAmbiguousCheckBox = FindName("ExcludeAmbiguousCheckBox") as CheckBox;

        // Hook up password generation settings
        if (passwordLengthSlider != null)
        {
            passwordLengthSlider.ValueChanged += (s, e) =>
            {
                int length = (int)passwordLengthSlider.Value;
                if (passwordLengthValue != null)
                    passwordLengthValue.Text = length.ToString();
                _passwordSettings.Length = length;
            };
        }
        
        if (includeUppercaseCheckBox != null)
        {
            includeUppercaseCheckBox.Checked += (s, e) => _passwordSettings.IncludeUppercase = true;
            includeUppercaseCheckBox.Unchecked += (s, e) => _passwordSettings.IncludeUppercase = false;
        }
        
        if (includeLowercaseCheckBox != null)
        {
            includeLowercaseCheckBox.Checked += (s, e) => _passwordSettings.IncludeLowercase = true;
            includeLowercaseCheckBox.Unchecked += (s, e) => _passwordSettings.IncludeLowercase = false;
        }
        
        if (includeDigitsCheckBox != null)
        {
            includeDigitsCheckBox.Checked += (s, e) => _passwordSettings.IncludeDigits = true;
            includeDigitsCheckBox.Unchecked += (s, e) => _passwordSettings.IncludeDigits = false;
        }
        
        if (includeSymbolsCheckBox != null)
        {
            includeSymbolsCheckBox.Checked += (s, e) => _passwordSettings.IncludeSymbols = true;
            includeSymbolsCheckBox.Unchecked += (s, e) => _passwordSettings.IncludeSymbols = false;
        }
        
        if (excludeAmbiguousCheckBox != null)
        {
            excludeAmbiguousCheckBox.Checked += (s, e) => _passwordSettings.ExcludeAmbiguous = true;
            excludeAmbiguousCheckBox.Unchecked += (s, e) => _passwordSettings.ExcludeAmbiguous = false;
        }
    }

    private void SetSelectedCategory(string category)
    {
        foreach (var item in CategoryBox.Items)
        {
            if (item is ComboBoxItem comboItem &&
                string.Equals(comboItem.Content?.ToString(), category, StringComparison.OrdinalIgnoreCase))
            {
                CategoryBox.SelectedItem = comboItem;
                return;
            }
        }
    }
}
