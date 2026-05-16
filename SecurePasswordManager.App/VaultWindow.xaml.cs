using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using SecurePasswordManager.Core.Models;
using SecurePasswordManager.Core.Services;

namespace SecurePasswordManager.App;

public partial class VaultWindow : Window
{
    private VaultService? _vault;
    private List<PasswordEntry> _flatEntries = new();  // Keep flat list for operations
    private ObservableCollection<KeyValuePair<string, List<PasswordEntry>>> _categorizedEntries = new();
    private readonly ISessionManager _sessionManager = new SessionManager();
    private readonly SecureClipboard _secureClipboard = new SecureClipboard();
    private System.Windows.Threading.DispatcherTimer? _idleTimer;
    
    public VaultWindow(VaultService vault)
    {
        InitializeComponent();
        _vault = vault;
        EntriesItemsControl.ItemsSource = _categorizedEntries;
        
        // Phase 3: Initialize session management
        Loaded += OnWindowLoaded;
        
        LoadEntries();
    }
    
    private void OnWindowLoaded(object sender, RoutedEventArgs e)
    {
        // Phase 3-4: Start session timeout tracking with configured timeout
        if (_vault != null)
        {
            // Phase 4: Load timeout from AppSettings
            var settings = new SecurePasswordManager.Core.Utils.AppSettings();
            settings.Load();
            var configuredTimeout = settings.GetSessionTimeoutSeconds();
            
            _sessionManager.StartSession(_vault.VaultPath, configuredTimeout);
            _sessionManager.OnSessionTimeout += OnSessionTimeout;
            
            // Start UI timer to show remaining time
            StartIdleDisplayTimer();
        }
    }
    
    private void StartIdleDisplayTimer()
    {
        _idleTimer = new System.Windows.Threading.DispatcherTimer();
        _idleTimer.Interval = TimeSpan.FromSeconds(1);
        _idleTimer.Tick += (s, e) =>
        {
            var remaining = _sessionManager.GetRemainingSeconds();
            if (remaining >= 0)
            {
                var mins = remaining / 60;
                var secs = remaining % 60;
                VaultStatusText.Text = $"Session: {mins}m {secs:D2}s remaining";
            }
        };
        _idleTimer.Start();
    }
    
    private void OnSessionTimeout(string vaultPath)
    {
        // Phase 3: Auto-lock vault when session times out
        Dispatcher.Invoke(() =>
        {
            StatusText.Text = "[TIMEOUT] Session expired. Vault locked for security.";
            OnLockVault(this, new RoutedEventArgs());
        });
    }
    
    private async void LoadEntries()
    {
        try
        {
            if (_vault == null)
                return;
            
            _flatEntries.Clear();
            _categorizedEntries.Clear();
            var entries = await _vault.GetAllEntriesAsync();
            _flatEntries.AddRange(entries);

            // Apply any active search filter (will populate _categorizedEntries)
            ApplySearchFilter(SearchBox?.Text ?? string.Empty);

            var totalEntries = entries.Count();
            StatusText.Text = $"[OK] Loaded {totalEntries} password entries";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Error loading entries: {ex.Message}";
        }
    }

    private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        ApplySearchFilter(SearchBox?.Text ?? string.Empty);
    }

    private void ApplySearchFilter(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            // Show all
            RefreshCategories();
            VaultStatusText.Text = $"Vault: {_flatEntries.Count} entries in {_flatEntries.GroupBy(en => en.Category ?? "Other").Count()} categories";
            return;
        }

        var q = query.Trim().ToLowerInvariant();
        var filtered = _flatEntries.Where(en =>
            (!string.IsNullOrEmpty(en.ServiceName) && en.ServiceName.ToLowerInvariant().Contains(q)) ||
            (!string.IsNullOrEmpty(en.Url) && en.Url.ToLowerInvariant().Contains(q))
        ).ToList();

        // Rebuild categorized view from filtered list
        _categorizedEntries.Clear();
        var grouped = filtered
            .GroupBy(e => e.Category ?? "Other")
            .OrderBy(g => g.Key);

        foreach (var group in grouped)
        {
            _categorizedEntries.Add(new KeyValuePair<string, List<PasswordEntry>>(group.Key, group.ToList()));
        }

        VaultStatusText.Text = $"Search: showing {filtered.Count}/{_flatEntries.Count} entries in {grouped.Count()} categories";
    }
    
    private void RefreshCategories()
    {
        // Rebuild categorized view from flat list
        _categorizedEntries.Clear();
        var grouped = _flatEntries
            .GroupBy(e => e.Category ?? "Other")
            .OrderBy(g => g.Key)
            .ToDictionary(g => g.Key, g => g.ToList());
        
        foreach (var group in grouped)
        {
            _categorizedEntries.Add(new KeyValuePair<string, List<PasswordEntry>>(group.Key, group.Value));
        }
    }
    
    private void OnAddEntry(object sender, RoutedEventArgs e)
    {
        _sessionManager.BumpActivity(); // Phase 3: Reset session timer on user action
        
        var dialog = new EntryWindow();
        if (dialog.ShowDialog() == true)
        {
            var entry = dialog.GetEntry();
            AddEntryToVault(entry);
        }
    }
    
    private async void AddEntryToVault(PasswordEntry entry)
    {
        try
        {
            if (_vault == null)
                return;
            
            var id = await _vault.AddEntryAsync(entry);
            entry.Id = id;
            _flatEntries.Add(entry);
            RefreshCategories();
            
            StatusText.Text = $"[OK] Added '{entry.ServiceName}' to vault";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Error adding entry: {ex.Message}";
        }
    }
    
    private void OnEditEntry(object sender, RoutedEventArgs e)
    {
        _sessionManager.BumpActivity();

        if ((sender as FrameworkElement)?.DataContext is not PasswordEntry entry)
            return;
        
        var dialog = new EntryWindow(entry);
        if (dialog.ShowDialog() == true)
        {
            var updatedEntry = dialog.GetEntry();
            UpdateEntryInVault(updatedEntry);
        }
    }
    
    private async void UpdateEntryInVault(PasswordEntry entry)
    {
        try
        {
            _sessionManager.BumpActivity();

            if (_vault == null)
                return;
            
            await _vault.UpdateEntryAsync(entry);
            
            int index = -1;
            for (int i = 0; i < _flatEntries.Count; i++)
            {
                if (_flatEntries[i].Id == entry.Id)
                {
                    index = i;
                    break;
                }
            }

            if (index >= 0)
            {
                _flatEntries[index] = entry;
            }
            
            RefreshCategories();
            
            StatusText.Text = $"[OK] Updated '{entry.ServiceName}'";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Error updating entry: {ex.Message}";
        }
    }
    
    private void OnDeleteEntry(object sender, RoutedEventArgs e)
    {
        _sessionManager.BumpActivity();

        if ((sender as FrameworkElement)?.DataContext is not PasswordEntry entry)
            return;
        
        var result = MessageBox.Show(
            $"Delete '{entry.ServiceName}'?\n\nThis cannot be undone.",
            "Confirm Delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        
        if (result == MessageBoxResult.Yes)
        {
            DeleteEntryFromVault(entry.Id, entry.ServiceName);
        }
    }
    
    private async void DeleteEntryFromVault(long entryId, string? serviceName = null)
    {
        try
        {
            _sessionManager.BumpActivity();

            if (_vault == null || entryId == 0)
                return;
            
            await _vault.DeleteEntryAsync(entryId);

            int index = -1;
            for (int i = 0; i < _flatEntries.Count; i++)
            {
                if (_flatEntries[i].Id == entryId)
                {
                    index = i;
                    break;
                }
            }

            if (index >= 0)
            {
                _flatEntries.RemoveAt(index);
            }
            
            RefreshCategories();
            
            StatusText.Text = $"[OK] Deleted '{serviceName ?? "entry"}'";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Error deleting entry: {ex.Message}";
        }
    }

    private void OnCopyPassword(object sender, RoutedEventArgs e)
    {
        _sessionManager.BumpActivity();

        if ((sender as FrameworkElement)?.DataContext is not PasswordEntry entry)
            return;

        if (string.IsNullOrEmpty(entry.Password))
        {
            StatusText.Text = $"[ERROR] No password available for '{entry.ServiceName}'";
            return;
        }

        try
        {
            _secureClipboard.CopyPasswordToClipboard(entry.Password, _vault?.VaultPath);
            StatusText.Text = $"[OK] Password copied for '{entry.ServiceName}' (clears in 30s)";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Error copying password: {ex.Message}";
        }
    }

    private void OnViewPassword(object sender, RoutedEventArgs e)
    {
        _sessionManager.BumpActivity();

        if ((sender as FrameworkElement)?.DataContext is not PasswordEntry entry)
            return;

        if (string.IsNullOrEmpty(entry.Password))
        {
            StatusText.Text = $"[ERROR] No password available for '{entry.ServiceName}'";
            return;
        }

        MessageBox.Show(
            $"Service: {entry.ServiceName}\nUsername: {entry.Username}\n\nPassword:\n{entry.Password}",
            $"View Password - {entry.ServiceName}",
            MessageBoxButton.OK,
            MessageBoxImage.Information);

        StatusText.Text = $"[OK] Password viewed for '{entry.ServiceName}'";
    }
    
    private void OnRefresh(object sender, RoutedEventArgs e)
    {
        LoadEntries();
    }
    
    private void OnLockVault(object sender, RoutedEventArgs e)
    {
        // Phase 3: End session
        if (_vault != null)
        {
            _sessionManager.EndSession(_vault.VaultPath);
            _vault.Lock();
        }

        _secureClipboard.ClearClipboard();
        
        // Stop idle timer
        if (_idleTimer != null)
        {
            _idleTimer.Stop();
            _idleTimer = null;
        }
        
        var mainWindow = new MainWindow();
        mainWindow.Show();
        Close();
    }
    
    private void OnSettings(object sender, RoutedEventArgs e)
    {
        // Phase 4: Open settings window
        _sessionManager.BumpActivity();
        
        var settingsWindow = new SettingsWindow(_vault)
        {
            Owner = this
        };
        
        if (settingsWindow.ShowDialog() == true)
        {
            // Reload settings from AppSettings and update SessionManager
            var settings = new SecurePasswordManager.Core.Utils.AppSettings();
            settings.Load();
            var newTimeout = settings.GetSessionTimeoutSeconds();
            
            // Restart session with new timeout
            if (_vault != null)
            {
                _sessionManager.EndSession(_vault.VaultPath);
                _sessionManager.StartSession(_vault.VaultPath, newTimeout);
                StatusText.Text = $"[OK] Settings saved (session timeout: {settings.GetSessionTimeoutMinutes()} min)";
            }
        }
    }
    
    private async void OnImportPasswords(object sender, RoutedEventArgs e)
    {
        // Phase 4: Import passwords from file
        _sessionManager.BumpActivity();
        
        try
        {
            if (_vault == null)
            {
                StatusText.Text = "[ERROR] Vault is not available";
                return;
            }

            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Import Passwords",
                Filter = "All Supported (*.csv;*.json)|*.csv;*.json|CSV Files (*.csv)|*.csv|JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                FilterIndex = 0
            };
            
            if (dialog.ShowDialog() != true)
                return;
            
            // Parse imported file
            List<PasswordEntry> importedEntries;
            try
            {
                var ext = System.IO.Path.GetExtension(dialog.FileName).ToLower();
                importedEntries = ext == ".json" 
                    ? ImportService.ImportFromJson(dialog.FileName)
                    : ImportService.ImportFromCsv(dialog.FileName);
            }
            catch (Exception ex)
            {
                StatusText.Text = $"[ERROR] Failed to parse file: {ex.Message}";
                return;
            }
            
            if (importedEntries.Count == 0)
            {
                StatusText.Text = "[ERROR] No valid password entries found in file";
                return;
            }
            
            // Check for duplicates
            var duplicates = ImportService.DetectDuplicates(importedEntries, _flatEntries);
            var conflictActions = new Dictionary<int, ImportConflictAction>();
            
            if (duplicates.Count > 0)
            {
                var conflictDialog = new ImportConflictDialog(duplicates)
                {
                    Owner = this
                };
                
                if (conflictDialog.ShowDialog() != true)
                {
                    StatusText.Text = "[ERROR] Import cancelled by user";
                    return;
                }
                
                conflictActions = conflictDialog.ConflictActions;
            }
            
            // Import entries to vault
            int imported = 0;
            int skipped = 0;
            
            for (int i = 0; i < importedEntries.Count; i++)
            {
                var action = conflictActions.ContainsKey(i) ? conflictActions[i] : ImportConflictAction.KeepBoth;
                var importedEntry = importedEntries[i];
                var importedServiceName = importedEntry.ServiceName ?? "(unknown)";
                
                if (action == ImportConflictAction.Skip)
                {
                    skipped++;
                    continue;
                }
                
                try
                {
                    if (action == ImportConflictAction.Overwrite)
                    {
                        // Find and update existing entry
                        var existingEntry = _flatEntries.FirstOrDefault(e =>
                            string.Equals(e.ServiceName ?? string.Empty, importedServiceName, StringComparison.OrdinalIgnoreCase));
                        
                        if (existingEntry != null)
                        {
                            existingEntry.Username = importedEntry.Username;
                            existingEntry.Password = importedEntry.Password;
                            existingEntry.Url = importedEntry.Url;
                            existingEntry.Notes = importedEntry.Notes;
                            existingEntry.Category = importedEntry.Category;
                            existingEntry.ModifiedAt = DateTime.UtcNow;
                            
                            await _vault.UpdateEntryAsync(existingEntry);
                            imported++;
                        }
                    }
                    else // KeepBoth
                    {
                        var id = await _vault.AddEntryAsync(importedEntry);
                        importedEntry.Id = id;
                        _flatEntries.Add(importedEntry);
                        imported++;
                    }
                }
                catch (Exception ex)
                {
                    StatusText.Text = $"[ERROR] Failed to import entry '{importedServiceName}': {ex.Message}";
                    return;
                }
            }
            
            RefreshCategories();
            StatusText.Text = $"[OK] Imported {imported} password entries{(skipped > 0 ? $" (skipped {skipped})" : "")}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Import failed: {ex.Message}";
        }
    }
    
    private void OnExportPasswords(object sender, RoutedEventArgs e)
    {
        // Phase 5: Export passwords
        _sessionManager.BumpActivity();
        
        try
        {
            // Show export options dialog
            var optionsDialog = new ExportOptionsDialog
            {
                Owner = this
            };
            
            if (optionsDialog.ShowDialog() != true)
                return;
            
            // If exporting encrypted, require master password re-entry
            string? masterPassword = null;
            if (optionsDialog.EncryptExport)
            {
                var passwordPrompt = new PasswordPromptDialog
                {
                    Owner = this,
                    Title = "Master Password Required",
                    Message = "Enter your master password to create encrypted export"
                };
                
                if (passwordPrompt.ShowDialog() != true)
                {
                    StatusText.Text = "[ERROR] Export cancelled - master password not provided";
                    return;
                }
                
                masterPassword = passwordPrompt.Password;
            }
            
            // Show save dialog
            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export Passwords",
                Filter = optionsDialog.ExportAsJson 
                    ? "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
                    : "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                FileName = $"passwords_export_{DateTime.Now:yyyyMMdd_HHmmss}" + (optionsDialog.ExportAsJson ? ".json" : ".csv"),
                FilterIndex = 0
            };
            
            if (saveDialog.ShowDialog() != true)
            {
                StatusText.Text = "[ERROR] Export cancelled by user";
                return;
            }
            
            // Generate export content
            string exportContent;
            
            try
            {
                if (optionsDialog.ExportAsJson)
                {
                    exportContent = optionsDialog.EncryptExport
                        ? ExportService.ExportToEncryptedJson(_flatEntries, masterPassword!)
                        : ExportService.ExportToJson(_flatEntries, false);
                }
                else
                {
                    exportContent = ExportService.ExportToCsv(_flatEntries, optionsDialog.EncryptExport);
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = $"[ERROR] Failed to generate export: {ex.Message}";
                return;
            }
            
            // Save to file
            try
            {
                ExportService.SaveToFile(saveDialog.FileName, exportContent);
                
                var fileSize = new System.IO.FileInfo(saveDialog.FileName).Length;
                StatusText.Text = $"[OK] Exported {_flatEntries.Count} passwords to {System.IO.Path.GetFileName(saveDialog.FileName)} ({fileSize} bytes)";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"[ERROR] Failed to save export: {ex.Message}";
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = $"[ERROR] Export failed: {ex.Message}";
        }
    }
    
    private void OnWindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        // Phase 3: Stop idle timer and cleanup session
        if (_idleTimer != null)
        {
            _idleTimer.Stop();
            _idleTimer = null;
        }
        
        if (_vault != null)
        {
            _sessionManager.EndSession(_vault.VaultPath);
            
            if (_vault.IsUnlocked)
            {
                var result = MessageBox.Show(
                    "Lock vault before closing?",
                    "Confirm Close",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);
                
                if (result == MessageBoxResult.Yes)
                {
                    _vault.Lock();
                }
            }
        }
        
        _vault?.Dispose();
        _secureClipboard.ClearClipboard();
        
        // Cleanup session manager
        if (_sessionManager is SessionManager sm)
            sm.Dispose();
    }
}
