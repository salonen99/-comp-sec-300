using System;
using System.Collections.Generic;

namespace SecurePasswordManager.App
{
    // Local AuthService fallback for App UI to avoid build-time Core dependency issues
    public class AuthService
    {
        private const int MAX_UNLOCK_ATTEMPTS = 5;
        private const int LOCKOUT_DURATION_MINUTES = 5;

        private class LockoutState
        {
            public volatile int FailedAttempts;
            public DateTime LockoutStartTime;
            public bool IsLockedOut;
        }

        private readonly Dictionary<string, LockoutState> _vaultLockouts = new();
        private readonly object _lockObj = new();

        public bool ValidateUnlockAttempt(string vaultPath, bool isValidPassword)
        {
            if (string.IsNullOrWhiteSpace(vaultPath))
                throw new ArgumentException("Vault path cannot be null or empty", nameof(vaultPath));

            lock (_lockObj)
            {
                if (!_vaultLockouts.ContainsKey(vaultPath))
                {
                    _vaultLockouts[vaultPath] = new LockoutState { FailedAttempts = 0, IsLockedOut = false };
                }

                var state = _vaultLockouts[vaultPath];

                if (state.IsLockedOut)
                {
                    var elapsed = DateTime.UtcNow - state.LockoutStartTime;
                    if (elapsed < TimeSpan.FromMinutes(LOCKOUT_DURATION_MINUTES))
                    {
                        return false;
                    }
                    else
                    {
                        state.IsLockedOut = false;
                        state.FailedAttempts = 0;
                    }
                }

                if (isValidPassword)
                {
                    state.FailedAttempts = 0;
                    state.IsLockedOut = false;
                    return true;
                }
                else
                {
                    state.FailedAttempts++;
                    if (state.FailedAttempts >= MAX_UNLOCK_ATTEMPTS)
                    {
                        state.IsLockedOut = true;
                        state.LockoutStartTime = DateTime.UtcNow;
                        return false;
                    }
                    return true;
                }
            }
        }

        public bool IsLockedOut(string vaultPath)
        {
            if (string.IsNullOrWhiteSpace(vaultPath))
                return false;

            lock (_lockObj)
            {
                if (!_vaultLockouts.ContainsKey(vaultPath)) return false;
                var state = _vaultLockouts[vaultPath];
                if (!state.IsLockedOut) return false;
                var elapsed = DateTime.UtcNow - state.LockoutStartTime;
                if (elapsed >= TimeSpan.FromMinutes(LOCKOUT_DURATION_MINUTES))
                {
                    state.IsLockedOut = false;
                    state.FailedAttempts = 0;
                    return false;
                }
                return true;
            }
        }

        public TimeSpan GetLockoutTimeRemaining(string vaultPath)
        {
            if (string.IsNullOrWhiteSpace(vaultPath)) return TimeSpan.Zero;
            lock (_lockObj)
            {
                if (!_vaultLockouts.ContainsKey(vaultPath)) return TimeSpan.Zero;
                var state = _vaultLockouts[vaultPath];
                if (!state.IsLockedOut) return TimeSpan.Zero;
                var elapsed = DateTime.UtcNow - state.LockoutStartTime;
                var remaining = TimeSpan.FromMinutes(LOCKOUT_DURATION_MINUTES) - elapsed;
                return remaining < TimeSpan.Zero ? TimeSpan.Zero : remaining;
            }
        }

        public int GetFailedAttemptCount(string vaultPath)
        {
            if (string.IsNullOrWhiteSpace(vaultPath)) return 0;
            lock (_lockObj)
            {
                if (!_vaultLockouts.ContainsKey(vaultPath)) return 0;
                return _vaultLockouts[vaultPath].FailedAttempts;
            }
        }
    }
}
