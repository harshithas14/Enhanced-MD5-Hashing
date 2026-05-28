using System;
using System.Security.Cryptography;
using System.Text;

namespace EnhancedMD5Auth.Core
{
    /// <summary>
    /// Result returned by the full hashing pipeline.
    /// Stores every intermediate value for educational display.
    /// </summary>
    public class HashResult
    {
        public string OriginalPassword { get; set; }
        public string Salt             { get; set; }
        public string Pepper           { get; set; }
        public int    Iterations       { get; set; }

        // Stage outputs
        public string AfterSalt        { get; set; }   // password + salt
        public string AfterPepper      { get; set; }   // password + salt + pepper
        public string FirstMD5         { get; set; }   // MD5(salted+peppered)
        public string FinalHash        { get; set; }   // after iterative strengthening
    }

    /// <summary>
    /// Core enhanced MD5 hasher.
    ///
    /// Pipeline:
    ///   1. Generate a cryptographically-random salt (32 hex chars = 16 bytes).
    ///   2. Combine  password + salt + PEPPER (server-side secret).
    ///   3. Compute MD5 of the combined string → base hash.
    ///   4. Iterate: hash = MD5(hash + salt) repeated <iterations> times
    ///      (key-stretching / iterative strengthening).
    ///   5. Return the final hex digest.
    /// </summary>
    public class EnhancedMD5Hasher
    {
        // ── Configuration ────────────────────────────────────────────────────
        // In production the pepper comes from a secrets manager / env variable.
        private const string PEPPER        = "Xk9#mP2$vQ7@nL4!";
        private const int    SALT_BYTES    = 16;   // 128-bit salt
        public  const int    DEFAULT_ITER  = 10_000;

        // ── Public API ───────────────────────────────────────────────────────

        /// <summary>Hash a password with auto-generated salt and default iterations.</summary>
        public HashResult HashPasswordWithDetails(string password)
        {
            string salt       = GenerateSalt();
            int    iterations = DEFAULT_ITER;
            return BuildResult(password, salt, iterations);
        }

        /// <summary>Hash using a previously stored salt and iteration count (for verification).</summary>
        public string HashWithStoredParams(string password, string salt, int iterations)
            => BuildResult(password, salt, iterations).FinalHash;

        /// <summary>Hash with a specific iteration count (used by the benchmark).</summary>
        public string HashWithIterations(string password, int iterations)
            => BuildResult(password, GenerateSalt(), iterations).FinalHash;

        // ── Internal pipeline ────────────────────────────────────────────────

        private HashResult BuildResult(string password, string salt, int iterations)
        {
            // Stage 1 – salt combination
            string salted  = password + salt;

            // Stage 2 – pepper combination
            string peppered = salted + PEPPER;

            // Stage 3 – first MD5
            string firstMD5 = ComputeMD5(peppered);

            // Stage 4 – iterative strengthening
            string current = firstMD5;
            for (int i = 0; i < iterations; i++)
                current = ComputeMD5(current + salt);

            return new HashResult
            {
                OriginalPassword = password,
                Salt             = salt,
                Pepper           = PEPPER,
                Iterations       = iterations,
                AfterSalt        = salted,
                AfterPepper      = peppered,
                FirstMD5         = firstMD5,
                FinalHash        = current,
            };
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private string GenerateSalt()
        {
            byte[] bytes = new byte[SALT_BYTES];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Convert.ToHexString(bytes).ToLower();
        }

        internal static string ComputeMD5(string input)
        {
            byte[] bytes = MD5.HashData(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes).ToLower();
        }
    }
}
