using System;
using System.Security.Cryptography;
using System.Text;

namespace EnhancedMD5Auth.Core
{
    /// <summary>
    /// Static utility methods used across the project.
    /// </summary>
    public static class HashingUtils
    {
        // ── Plain MD5 (for contrast / educational demo) ──────────────────────

        /// <summary>
        /// Computes a plain (unsalted, unpeppered) MD5 hash.
        /// Exposed only for the attack-resistance demonstration.
        /// Do NOT use this for real authentication.
        /// </summary>
        public static string PlainMD5(string input)
        {
            byte[] bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes).ToLower();
        }

        // ── Constant-time comparison ─────────────────────────────────────────

        /// <summary>
        /// Compares two strings in constant time to prevent timing attacks.
        /// Returns true only when both strings are identical.
        ///
        /// Standard string equality short-circuits on the first mismatch,
        /// leaking timing information that an attacker can use to guess
        /// characters one by one. This method always touches every byte.
        /// </summary>
        public static bool SecureCompare(string a, string b)
        {
            // Convert to bytes so we work at a fixed granularity
            byte[] bytesA = Encoding.UTF8.GetBytes(a ?? "");
            byte[] bytesB = Encoding.UTF8.GetBytes(b ?? "");

            // XOR-fold all bytes; if any differ, 'diff' will be non-zero.
            // We always iterate max(len) iterations regardless of lengths.
            int maxLen = Math.Max(bytesA.Length, bytesB.Length);
            int diff   = bytesA.Length ^ bytesB.Length; // length mismatch also counts

            for (int i = 0; i < maxLen; i++)
            {
                byte ba = i < bytesA.Length ? bytesA[i] : (byte)0;
                byte bb = i < bytesB.Length ? bytesB[i] : (byte)0;
                diff |= ba ^ bb;
            }

            return diff == 0;
        }

        // ── Entropy estimation ───────────────────────────────────────────────

        /// <summary>
        /// Rough Shannon-entropy estimate for a password string.
        /// Used in the UI strength indicator.
        /// </summary>
        public static double EstimateEntropy(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;

            // Count character-class pool size
            int pool = 0;
            bool hasLower  = false, hasUpper = false,
                 hasDigit  = false, hasSymbol = false;

            foreach (char c in password)
            {
                if (char.IsLower(c))  hasLower  = true;
                if (char.IsUpper(c))  hasUpper  = true;
                if (char.IsDigit(c))  hasDigit  = true;
                if (!char.IsLetterOrDigit(c)) hasSymbol = true;
            }

            if (hasLower)  pool += 26;
            if (hasUpper)  pool += 26;
            if (hasDigit)  pool += 10;
            if (hasSymbol) pool += 32;

            if (pool == 0) pool = 26; // fallback

            return password.Length * Math.Log2(pool);
        }

        /// <summary>Returns a human-readable strength label for a given entropy value.</summary>
        public static (string label, ConsoleColor color) StrengthLabel(double entropy)
        {
            if (entropy < 28)  return ("Very Weak",  ConsoleColor.Red);
            if (entropy < 36)  return ("Weak",        ConsoleColor.DarkYellow);
            if (entropy < 60)  return ("Moderate",    ConsoleColor.Yellow);
            if (entropy < 80)  return ("Strong",       ConsoleColor.Green);
            return                    ("Very Strong",  ConsoleColor.Cyan);
        }
    }
}
