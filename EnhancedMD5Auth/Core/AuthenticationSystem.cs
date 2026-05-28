using System;
using System.Collections.Generic;
using EnhancedMD5Auth.UI;

namespace EnhancedMD5Auth.Core
{
    /// <summary>
    /// Represents a single stored user record in the (in-memory) database.
    /// In a real application this would be a database row.
    /// We NEVER store the plaintext password – only the hash + metadata.
    /// </summary>
    public class UserRecord
    {
        public string Username   { get; set; }
        public string Salt       { get; set; }
        public int    Iterations { get; set; }
        public string Hash       { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    /// <summary>
    /// Simulates a complete authentication system:
    ///   • Register  – hash and store credentials
    ///   • Login     – verify supplied password against stored hash
    ///   • ListUsers – display all registered accounts (hashes only)
    /// </summary>
    public class AuthenticationSystem
    {
        private readonly Dictionary<string, UserRecord> _store = new(StringComparer.OrdinalIgnoreCase);
        private readonly EnhancedMD5Hasher _hasher = new();

        // ── Public Methods ───────────────────────────────────────────────────

        /// <summary>
        /// Register a new user.
        /// Returns false if the username is already taken.
        /// </summary>
        public bool Register(string username, string password)
        {
            if (_store.ContainsKey(username))
            {
                ConsoleUI.ShowError($"  [REGISTER] Username '{username}' already exists.");
                return false;
            }

            var result = _hasher.HashPasswordWithDetails(password);

            _store[username] = new UserRecord
            {
                Username   = username,
                Salt       = result.Salt,
                Iterations = result.Iterations,
                Hash       = result.FinalHash,
                CreatedAt  = DateTime.UtcNow,
            };

            return true;
        }

        /// <summary>
        /// Attempt to log in.
        /// Re-hashes the supplied password with the stored salt+iterations,
        /// then compares using constant-time comparison.
        /// </summary>
        public bool Login(string username, string password)
        {
            if (!_store.TryGetValue(username, out UserRecord record))
                return false;   // user not found

            string computedHash = _hasher.HashWithStoredParams(
                password, record.Salt, record.Iterations);

            return HashingUtils.SecureCompare(record.Hash, computedHash);
        }

        /// <summary>
        /// Change a user's password, verifying the current password first.
        /// </summary>
        public bool ChangePassword(string username, string currentPassword, string newPassword)
        {
            if (!_store.TryGetValue(username, out UserRecord record))
                return false;

            string currentHash = _hasher.HashWithStoredParams(
                currentPassword, record.Salt, record.Iterations);

            if (!HashingUtils.SecureCompare(record.Hash, currentHash))
                return false;

            var result = _hasher.HashPasswordWithDetails(newPassword);

            record.Salt = result.Salt;
            record.Iterations = result.Iterations;
            record.Hash = result.FinalHash;
            return true;
        }

        /// <summary>Returns a read-only view of all stored records.</summary>
        public IEnumerable<UserRecord> GetAllUsers() => _store.Values;
    }
}
