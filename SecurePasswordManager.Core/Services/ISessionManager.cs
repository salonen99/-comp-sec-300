using System;

namespace SecurePasswordManager.Core.Services
{
    /// <summary>
    /// ISessionManager defines the contract for managing session lifecycle and idle timeout.
    /// 
    /// Security (CWE-613 - Session Timeout):
    /// - Tracks active sessions per vault
    /// - Fires OnSessionTimeout event when idle time expires
    /// - Automatically locks vault on timeout
    /// </summary>
    public interface ISessionManager
    {
        /// <summary>
        /// Fired when a session times out due to inactivity.
        /// </summary>
        event Action<string> OnSessionTimeout;

        /// <summary>
        /// Starts a new session for a vault.
        /// </summary>
        /// <param name="vaultPath">Absolute path to vault file</param>
        /// <param name="timeoutSeconds">Inactivity timeout in seconds (default 900 = 15 minutes)</param>
        void StartSession(string vaultPath, int timeoutSeconds = 900);

        /// <summary>
        /// Bumps the activity timer, resetting the idle countdown.
        /// Call this whenever the user interacts with the vault.
        /// </summary>
        void BumpActivity();

        /// <summary>
        /// Ends a session (called when vault is locked).
        /// </summary>
        void EndSession(string vaultPath);

        /// <summary>
        /// Gets the remaining seconds until session timeout.
        /// Returns -1 if no active session.
        /// </summary>
        int GetRemainingSeconds();

        /// <summary>
        /// Gets the currently active vault path, or null if no session.
        /// </summary>
        string? GetActiveVaultPath();

        /// <summary>
        /// Gets the configured timeout in seconds.
        /// </summary>
        int GetConfiguredTimeoutSeconds();

        /// <summary>
        /// Updates the timeout duration for the current session.
        /// </summary>
        void UpdateTimeoutDuration(int timeoutSeconds);

        /// <summary>
        /// Checks if a session is currently active.
        /// </summary>
        bool IsSessionActive();

        /// <summary>
        /// Phase 6: Mark MFA as verified for this session.
        /// </summary>
        void MarkMfaVerified();

        /// <summary>
        /// Phase 6: Get when MFA was last verified (null if not verified).
        /// </summary>
        DateTime? GetMfaVerifiedAt();

        /// <summary>
        /// Phase 6: Check if MFA is currently verified within the 24-hour window.
        /// </summary>
        bool IsMfaVerified();

        /// <summary>
        /// Phase 6: Clear MFA verification state.
        /// </summary>
        void ClearMfaVerificationState();
    }
}
