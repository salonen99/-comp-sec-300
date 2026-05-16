using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.App;

/// <summary>
/// Dialog for handling import conflicts (duplicate entries).
/// Returns a dictionary mapping entry index to conflict action.
/// </summary>
public partial class ImportConflictDialog : Window
{
    public Dictionary<int, ImportConflictAction> ConflictActions { get; private set; } = new();
    
    private List<ConflictItem> _conflicts = new();

    public ImportConflictDialog(Dictionary<int, string> duplicates)
    {
        InitializeComponent();
        
        // Build conflict items
        foreach (var dup in duplicates)
        {
            _conflicts.Add(new ConflictItem { Index = dup.Key, ServiceName = dup.Value });
        }
        
        ConflictListBox.ItemsSource = _conflicts;
    }

    private void OnImport(object sender, RoutedEventArgs e)
    {
        ConflictActions.Clear();
        
        // Extract actions from radio button selections
        var radioButtons = GetAllRadioButtons(ConflictListBox);
        
        foreach (var radioBtn in radioButtons)
        {
            if (radioBtn.IsChecked == true && radioBtn.Tag is int index)
            {
                var content = radioBtn.Content?.ToString() ?? "";
                var action = content switch
                {
                    "Skip this entry" => ImportConflictAction.Skip,
                    "Overwrite existing" => ImportConflictAction.Overwrite,
                    "Keep both" => ImportConflictAction.KeepBoth,
                    _ => ImportConflictAction.Skip
                };
                
                ConflictActions[index] = action;
            }
        }
        
        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private List<RadioButton> GetAllRadioButtons(DependencyObject parent)
    {
        var buttons = new List<RadioButton>();
        
        for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);
            
            if (child is RadioButton radioBtn)
                buttons.Add(radioBtn);
            
            buttons.AddRange(GetAllRadioButtons(child));
        }
        
        return buttons;
    }

    private class ConflictItem
    {
        public int Index { get; set; }
        public string ServiceName { get; set; } = "";
    }
}
