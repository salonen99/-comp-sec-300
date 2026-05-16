using System;
using System.IO;

namespace SecurePasswordManager.Core.Services
{
    /// <summary>
    /// Simple file-based vault lock to prevent concurrent access.
    /// Creates/open a .lock file and holds an exclusive FileStream.
    /// </summary>
    public static class VaultLock
    {
        public static FileStream LockVaultFile(string vaultPath)
        {
            if (string.IsNullOrWhiteSpace(vaultPath))
                throw new ArgumentException("Vault path required", nameof(vaultPath));

            var lockFile = vaultPath + ".lock";

            // Ensure directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(vaultPath) ?? ".");

            // Open or create lock file with exclusive access
            var fs = new FileStream(lockFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

            // Optionally write PID/timestamp for diagnostics
            try
            {
                var info = System.Text.Encoding.UTF8.GetBytes($"Locked:{Environment.ProcessId}:{DateTime.UtcNow:o}\n");
                fs.SetLength(0);
                fs.Write(info, 0, info.Length);
                fs.Flush(true);
            }
            catch
            {
                // Ignore write failures
            }

            return fs;
        }
    }
}
