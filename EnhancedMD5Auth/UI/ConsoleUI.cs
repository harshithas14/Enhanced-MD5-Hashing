using System;
using EnhancedMD5Auth.Core;

namespace EnhancedMD5Auth.UI
{
    /// <summary>
    /// All console rendering logic lives here so Program.cs stays clean.
    /// </summary>
    public static class ConsoleUI
    {
        // ── Theme colours ────────────────────────────────────────────────────
        private static readonly ConsoleColor C_TITLE   = ConsoleColor.Cyan;
        private static readonly ConsoleColor C_HEADER  = ConsoleColor.Yellow;
        private static readonly ConsoleColor C_KEY     = ConsoleColor.DarkCyan;
        private static readonly ConsoleColor C_VALUE   = ConsoleColor.White;
        private static readonly ConsoleColor C_SUCCESS = ConsoleColor.Green;
        private static readonly ConsoleColor C_FAIL    = ConsoleColor.Red;
        private static readonly ConsoleColor C_INFO    = ConsoleColor.Gray;
        private static readonly ConsoleColor C_ACCENT  = ConsoleColor.Magenta;

        // ── Structural helpers ───────────────────────────────────────────────

        public static void Write(string text, ConsoleColor color)
        {
            ConsoleColor prev = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ForegroundColor = prev;
        }

        public static void WriteLine(string text, ConsoleColor color)
        {
            Write(text + "\n", color);
        }

        public static void ShowError(string msg)  => WriteLine(msg, C_FAIL);
        public static void ShowInfo(string msg)   => WriteLine(msg, C_INFO);
        public static void ShowSuccess(string msg)=> WriteLine(msg, C_SUCCESS);

        // ── Banner ───────────────────────────────────────────────────────────

        public static void ShowBanner()
        {
            Console.Clear();
            WriteLine(@"
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║          ENHANCED MD5 HASHING — SECURE AUTHENTICATION SYSTEM            ║
  ║     Salting  •  Peppering  •  Iterative Strengthening  •  Education     ║
  ╚══════════════════════════════════════════════════════════════════════════╝", C_TITLE);

            WriteLine("\n  This program demonstrates why plain MD5 is insecure and how", C_INFO);
            WriteLine("  layered defences (salt + pepper + iterations) mitigate real attacks.\n", C_INFO);
        }

        // ── Main menu ────────────────────────────────────────────────────────

        public static void ShowMainMenu()
        {
            WriteLine("  ┌─────────────────────────────────────────┐", C_HEADER);
            WriteLine("  │              MAIN  MENU                 │", C_HEADER);
            WriteLine("  ├─────────────────────────────────────────┤", C_HEADER);
            WriteLine("  │  1. Hashing Pipeline (step-by-step)     │", C_VALUE);
            WriteLine("  │  2. User Registration & Login           │", C_VALUE);
            WriteLine("  │  3. Attack Resistance Demo              │", C_VALUE);
            WriteLine("  │  4. Iteration Strength Benchmark        │", C_VALUE);
            WriteLine("  │  5. Interactive Hash Explorer           │", C_VALUE);
            WriteLine("  │  6. Change Password                     │", C_VALUE);
            WriteLine("  │  7. Exit                                │", C_VALUE);
            WriteLine("  └─────────────────────────────────────────┘", C_HEADER);
            Write("  Choose an option [1-7]: ", C_KEY);
        }

        // ── Section headers ──────────────────────────────────────────────────

        public static void ShowSectionHeader(string title)
        {
            Console.Clear();
            string bar = new('═', title.Length + 4);
            WriteLine($"\n  ╔{bar}╗", C_TITLE);
            WriteLine($"  ║  {title}  ║", C_TITLE);
            WriteLine($"  ╚{bar}╝\n", C_TITLE);
        }

        public static void ShowSubHeader(string title)
        {
            Console.WriteLine();
            WriteLine("  ┌─ " + title + " " + new string('─', Math.Max(0, 55 - title.Length)) + "┐", C_HEADER);
        }

        // ── Hashing pipeline display ─────────────────────────────────────────

        public static void ShowHashingSteps(string password, HashResult r)
        {
            double entropy = HashingUtils.EstimateEntropy(password);
            var (label, color) = HashingUtils.StrengthLabel(entropy);

            WriteLine("\n  Password Analysis", C_HEADER);
            KV("  Original Password", password);
            Write("  Password Strength  ", C_KEY);
            Write($": [{label}]", color);
            WriteLine($"  ({entropy:F1} bits of entropy)", C_INFO);

            WriteLine("\n  ── Stage 1: Salt Generation ──────────────────────────────────", C_ACCENT);
            ShowInfo("  A 128-bit (16-byte) cryptographically-random salt is generated.");
            ShowInfo("  Unique per password — prevents rainbow-table and reuse attacks.");
            KV("  Generated Salt", r.Salt);

            WriteLine("\n  ── Stage 2: Salt Combination ─────────────────────────────────", C_ACCENT);
            ShowInfo("  password + salt are concatenated.");
            KV("  Combined String", TruncateForDisplay(r.AfterSalt));

            WriteLine("\n  ── Stage 3: Pepper Application ───────────────────────────────", C_ACCENT);
            ShowInfo("  A server-side secret (pepper) is appended.");
            ShowInfo("  Even if the DB is stolen, the attacker still needs the pepper.");
            KV("  Pepper Value", r.Pepper);
            KV("  After Pepper", TruncateForDisplay(r.AfterPepper));

            WriteLine("\n  ── Stage 4: First MD5 Hash ───────────────────────────────────", C_ACCENT);
            KV("  MD5 Hash", r.FirstMD5);

            WriteLine("\n  ── Stage 5: Iterative Strengthening ──────────────────────────", C_ACCENT);
            ShowInfo($"  The hash is re-hashed MD5(hash + salt) × {r.Iterations:N0} times.");
            ShowInfo("  Each extra iteration multiplies attacker cost at negligible server cost.");
            KV("  Iterations", r.Iterations.ToString("N0"));
            KV("  Final Hash", r.FinalHash);

            WriteLine("\n  What gets stored in the database:", C_HEADER);
            KV("  salt",       r.Salt);
            KV("  iterations", r.Iterations.ToString("N0"));
            KV("  hash",       r.FinalHash);
            ShowInfo("\n  ✔  The original password is NEVER stored.");
        }

        // ── Registration / login results ─────────────────────────────────────

        public static void ShowRegistrationResult(string username, string password, bool success)
        {
            if (success)
                WriteLine($"  ✔  Registered  '{username}'  (password: {password})", C_SUCCESS);
            else
                WriteLine($"  ✖  Failed      '{username}'", C_FAIL);
        }

        public static void ShowLoginResult(string user, string pass, bool result, bool expected)
        {
            string status = result ? "✔  ACCESS GRANTED" : "✖  ACCESS DENIED ";
            string exp    = result == expected ? "" : "  [UNEXPECTED!]";
            var    col    = result ? C_SUCCESS : C_FAIL;
            WriteLine($"  {status}  user='{user}'  pass='{pass}'{exp}", col);
        }

        // ── Salt uniqueness demo ─────────────────────────────────────────────

        public static void ShowSaltDemo(int n, string hash, string salt)
        {
            Write($"  [{n}] hash=", C_KEY);
            Write(hash, C_VALUE);
            Write("  salt=", C_KEY);
            WriteLine(salt.Substring(0, 12) + "...", C_INFO);
        }

        // ── Benchmark ────────────────────────────────────────────────────────

        public static void ShowBenchmarkHeader()
        {
            Console.WriteLine();
            WriteLine("  Iterations       Time (ms)   Security estimate", C_HEADER);
            WriteLine("  " + new string('─', 55), C_INFO);
        }

        public static void ShowBenchmarkRow(int iterations, long ms)
        {
            string security;
            ConsoleColor secColor;

            if      (ms < 10)   { security = "Very Fast – too weak for production"; secColor = C_FAIL; }
            else if (ms < 100)  { security = "Moderate – acceptable minimum";       secColor = ConsoleColor.Yellow; }
            else if (ms < 500)  { security = "Good – recommended range";             secColor = C_SUCCESS; }
            else if (ms < 2000) { security = "Strong – ideal for sensitive data";    secColor = ConsoleColor.Cyan; }
            else                { security = "Very Strong – may impact UX";          secColor = ConsoleColor.Magenta; }

            Write($"  {iterations,12:N0}   {ms,8} ms   ", C_VALUE);
            WriteLine(security, secColor);
        }

        // ── Quick hash (interactive explorer) ────────────────────────────────

        public static void ShowQuickHash(HashResult r)
        {
            double entropy = HashingUtils.EstimateEntropy(r.OriginalPassword);
            var (label, col) = HashingUtils.StrengthLabel(entropy);

            Write($"\n  Strength: ", C_KEY);
            Write($"[{label}]", col);
            WriteLine($"  ({entropy:F1} bits)", C_INFO);
            KV("  Salt      ", r.Salt);
            KV("  Hash      ", r.FinalHash);
            Console.WriteLine();
        }

        // ── Misc ─────────────────────────────────────────────────────────────

        public static void ShowGoodbye()
        {
            Console.WriteLine();
            WriteLine("  Thank you for exploring Enhanced MD5 Authentication!", C_TITLE);
            WriteLine("  Remember: in production prefer Argon2id or bcrypt over MD5.", C_INFO);
            Console.WriteLine();
        }

        public static void Pause()
        {
            Console.WriteLine();
            Write("  Press any key to return to the menu...", C_INFO);
            Console.ReadKey(intercept: true);
            Console.Clear();
            ShowBanner();
        }

        // ── Private helpers ──────────────────────────────────────────────────

        private static void KV(string key, string value)
        {
            Write(key.PadRight(22) + ": ", C_KEY);
            WriteLine(value, C_VALUE);
        }

        private static string TruncateForDisplay(string s, int max = 60)
            => s.Length > max ? s.Substring(0, max) + "..." : s;
    }
}
