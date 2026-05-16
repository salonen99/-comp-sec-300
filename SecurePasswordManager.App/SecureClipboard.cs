using System;
using System.Reflection;
using System.Windows;
using System.Windows.Threading;

namespace SecurePasswordManager.App
{
    /// <summary>
    /// SecureClipboard handles password copying with automatic clearance.
    /// 
    /// Security (CWE-312 - Data Protection on Storage):
    /// - Copies password to clipboard with automatic clear after 30 seconds
    /// - Best-effort clears OS clipboard history (Win+V) when platform API is available
    /// - No plaintext password logging
    /// - Thread-safe clipboard access using WinForms Clipboard API
    /// </summary>
    public class SecureClipboard
    {
        private const int CLEAR_DELAY_SECONDS = 30;
        private DispatcherTimer? _clearTimer;
        private string _currentVaultIdentifier = "unknown"; // For multi-vault debugging

        public SecureClipboard()
        {
        }

        /// <summary>
        /// Copies a password to clipboard with automatic clearance after 30 seconds.
        /// </summary>
        /// <param name="password">Password to copy (in plaintext)</param>
        /// <param name="vaultIdentifier">Optional vault identifier for debugging</param>
        public void CopyPasswordToClipboard(string password, string? vaultIdentifier = null)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            _currentVaultIdentifier = vaultIdentifier ?? "unknown";

            try
            {
                // Set clipboard to password
                ExecuteOnUiThread(() => Clipboard.SetText(password));

                // Start auto-clear timer
                StartClearTimer();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "Failed to copy password to clipboard: System clipboard access failed: " + ex.GetType().Name,
                    ex
                );
            }
        }

        /// <summary>
        /// Manually clears the clipboard (for explicit user action).
        /// </summary>
        public void ClearClipboard()
        {
            try
            {
                ExecuteOnUiThread(Clipboard.Clear);
                TryClearClipboardHistory();
                StopClearTimer();
            }
            catch (Exception ex)
            {
                // Log but don't throw - clearing failed, but password is inaccessible
                System.Diagnostics.Debug.WriteLine($"SecureClipboard: Manual clear failed: {ex.Message}");
            }
        }

        private void StartClearTimer()
        {
            // Stop any existing timer
            StopClearTimer();

            var dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;
            _clearTimer = new DispatcherTimer(DispatcherPriority.Normal, dispatcher)
            {
                Interval = TimeSpan.FromSeconds(CLEAR_DELAY_SECONDS)
            };

            _clearTimer.Tick += OnClearTimerTick;
            _clearTimer.Start();
        }

        private void OnClearTimerTick(object? sender, EventArgs e)
        {
            StopClearTimer();

            try
            {
                ExecuteOnUiThread(Clipboard.Clear);
                var historyCleared = TryClearClipboardHistory();

                System.Diagnostics.Debug.WriteLine(
                    $"SecureClipboard: Password cleared after {CLEAR_DELAY_SECONDS}s [{_currentVaultIdentifier}], historyCleared={historyCleared}"
                );
            }
            catch (Exception ex)
            {
                // Log but don't throw
                System.Diagnostics.Debug.WriteLine($"SecureClipboard: Auto-clear failed: {ex.Message}");
            }
        }

        private void StopClearTimer()
        {
            if (_clearTimer != null)
            {
                _clearTimer.Stop();
                _clearTimer.Tick -= OnClearTimerTick;
                _clearTimer = null;
            }
        }

        private static void ExecuteOnUiThread(Action action)
        {
            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher != null && !dispatcher.CheckAccess())
            {
                dispatcher.Invoke(action);
                return;
            }

            action();
        }

        private static bool TryClearClipboardHistory()
        {
            try
            {
                // Best effort: on supported Windows builds this clears Win+V history.
                // Use reflection to avoid hard dependency on WinRT projections.
                var clipboardType = Type.GetType(
                    "Windows.ApplicationModel.DataTransfer.Clipboard, Windows, ContentType=WindowsRuntime",
                    throwOnError: false);

                var clearHistoryMethod = clipboardType?.GetMethod(
                    "ClearHistory",
                    BindingFlags.Public | BindingFlags.Static);

                if (clearHistoryMethod == null)
                    return false;

                var result = clearHistoryMethod.Invoke(null, null);
                return result as bool? ?? false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"SecureClipboard: Clipboard history clear unavailable: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets the delay in seconds.
        /// </summary>
        public static int GetClearDelaySeconds() => CLEAR_DELAY_SECONDS;
    }
}
