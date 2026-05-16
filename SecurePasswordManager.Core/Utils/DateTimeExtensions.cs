using System;

namespace SecurePasswordManager.Core.Utils
{
    public static class DateTimeExtensions
    {
        public static string ToIso8601String(this DateTime dt)
        {
            return dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
        }
    }
}
