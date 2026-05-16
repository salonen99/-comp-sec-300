using System;
using System.IO;
using System.Text.Json;

namespace SecurePasswordManager.Core.Utils
{
    public class AppSettings
    {
        private const string SettingsFileName = "settings.json";
        private string _settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SecurePasswordManager");

        public int SessionTimeoutMinutes { get; set; } = 15;

        // Phase 3: Password strength enforcement settings
        public bool EnforcePasswordStrength { get; set; } = false;
        public string MinPasswordStrengthLevel { get; set; } = "Fair";

        public void Load()
        {
            try
            {
                Directory.CreateDirectory(_settingsPath);
                var file = Path.Combine(_settingsPath, SettingsFileName);
                if (!File.Exists(file)) return;
                var json = File.ReadAllText(file);
                var s = JsonSerializer.Deserialize<AppSettings>(json);
                if (s != null) SessionTimeoutMinutes = s.SessionTimeoutMinutes;
            }
            catch
            {
                // ignore errors; use defaults
            }
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(_settingsPath);
                var file = Path.Combine(_settingsPath, SettingsFileName);
                var json = JsonSerializer.Serialize(this);
                File.WriteAllText(file, json);
            }
            catch
            {
                // ignore
            }
        }

        public int GetSessionTimeoutSeconds() => SessionTimeoutMinutes * 60;
        public int GetSessionTimeoutMinutes() => SessionTimeoutMinutes;
    }
}
