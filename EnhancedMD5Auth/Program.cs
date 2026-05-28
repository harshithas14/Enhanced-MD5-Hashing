using System;
using EnhancedMD5Auth.Core;
using EnhancedMD5Auth.UI;

namespace EnhancedMD5Auth
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "Enhanced MD5 Authentication System";
            ConsoleUI.ShowBanner();

            bool running = true;
            while (running)
            {
                ConsoleUI.ShowMainMenu();
                string choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1":
                        DemoHashingPipeline();
                        break;
                    case "2":
                        DemoUserRegistrationAndLogin();
                        break;
                    case "3":
                        DemoAttackResistance();
                        break;
                        case "4":
                        DemoBenchmark();
                        break;
                    case "5":
                        DemoInteractiveHash();
                        break;
                    case "6":
                        DemoChangePassword();
                        break;
                    case "7":
                        running = false;
                        ConsoleUI.ShowGoodbye();
                        break;
                    default:
                        ConsoleUI.ShowError("Invalid option. Please try again.");
                        break;
                }
            }
        }

        // ──────────────────────────────────────────────
        // DEMO 1 – Step-by-step hashing pipeline
        // ──────────────────────────────────────────────
        static void DemoHashingPipeline()
        {
            ConsoleUI.ShowSectionHeader("DEMO 1: Enhanced MD5 Hashing Pipeline");

            Console.Write("  Enter a password to hash: ");
            string password = Console.ReadLine() ?? "P@ssw0rd123";

            var hasher = new EnhancedMD5Hasher();
            var result = hasher.HashPasswordWithDetails(password);

            ConsoleUI.ShowHashingSteps(password, result);
            ConsoleUI.Pause();
        }

        // ──────────────────────────────────────────────
        // DEMO 2 – Simulated user registration + login
        // ──────────────────────────────────────────────
        static void DemoUserRegistrationAndLogin()
        {
            ConsoleUI.ShowSectionHeader("DEMO 2: User Registration & Login Simulation");

            var authSystem = new AuthenticationSystem();

            // Register three users
            string[] users = { "alice", "bob", "charlie" };
            string[] passwords = { "Alice@2024!", "Bobby#Secure99", "Charlie$Pass!" };

            ConsoleUI.ShowSubHeader("Registering users...");
            for (int i = 0; i < users.Length; i++)
            {
                bool ok = authSystem.Register(users[i], passwords[i]);
                ConsoleUI.ShowRegistrationResult(users[i], passwords[i], ok);
            }

            // Attempt duplicate registration
            ConsoleUI.ShowSubHeader("\nAttempting duplicate registration...");
            authSystem.Register("alice", "AnotherPass!");
            ConsoleUI.ShowInfo("  Duplicate 'alice' registration attempt rejected.");

            // Login attempts
            ConsoleUI.ShowSubHeader("\nLogin attempts...");
            var loginTests = new (string user, string pass, bool expected)[]
            {
                ("alice",   "Alice@2024!",   true),
                ("bob",     "WrongPass!",    false),
                ("charlie", "Charlie$Pass!", true),
                ("dave",    "NoUser123",     false),
            };

            foreach (var (user, pass, expected) in loginTests)
            {
                bool result = authSystem.Login(user, pass);
                ConsoleUI.ShowLoginResult(user, pass, result, expected);
            }

            ConsoleUI.Pause();
        }

        // ──────────────────────────────────────────────
        // DEMO 3 – Attack resistance
        // ──────────────────────────────────────────────
        static void DemoAttackResistance()
        {
            ConsoleUI.ShowSectionHeader("DEMO 3: Attack Resistance Demonstration");

            var hasher = new EnhancedMD5Hasher();
            string password = "SecurePassword!";

            ConsoleUI.ShowSubHeader("Salt uniqueness (same password → different hashes):");
            for (int i = 1; i <= 5; i++)
            {
                var r = hasher.HashPasswordWithDetails(password);
                ConsoleUI.ShowSaltDemo(i, r.FinalHash, r.Salt);
            }

            ConsoleUI.ShowSubHeader("\nRainbow-table resistance:");
            ConsoleUI.ShowInfo("  Plain MD5(\"" + password + "\")  = " + HashingUtils.PlainMD5(password));
            ConsoleUI.ShowInfo("  Enhanced hash is completely different each time (see above).");

            ConsoleUI.ShowSubHeader("\nTiming-attack resistance (constant-time comparison):");
            var stored = hasher.HashPasswordWithDetails(password);
            bool correct = HashingUtils.SecureCompare(stored.FinalHash,
                           hasher.HashWithStoredParams(password, stored.Salt, stored.Iterations));
            bool wrong   = HashingUtils.SecureCompare(stored.FinalHash,
                           hasher.HashWithStoredParams("WrongPass!", stored.Salt, stored.Iterations));
            ConsoleUI.ShowInfo($"  Correct password compare result : {correct}");
            ConsoleUI.ShowInfo($"  Wrong   password compare result : {wrong}");

            ConsoleUI.Pause();
        }

        // ──────────────────────────────────────────────
        // DEMO 4 – Iteration benchmark
        // ──────────────────────────────────────────────
        static void DemoBenchmark()
        {
            ConsoleUI.ShowSectionHeader("DEMO 4: Iteration Strength Benchmark");

            var hasher  = new EnhancedMD5Hasher();
            string pass = "BenchmarkPassword!";
            int[]  iters = { 100, 1_000, 10_000, 50_000, 100_000 };

            ConsoleUI.ShowBenchmarkHeader();
            foreach (int n in iters)
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                hasher.HashWithIterations(pass, n);
                sw.Stop();
                ConsoleUI.ShowBenchmarkRow(n, sw.ElapsedMilliseconds);
            }

            ConsoleUI.ShowInfo("\n  Higher iteration counts exponentially increase brute-force cost.");
            ConsoleUI.Pause();
        }

        // ──────────────────────────────────────────────
        // DEMO 5 – Interactive hash explorer
        // ──────────────────────────────────────────────
        static void DemoInteractiveHash()
        {
            ConsoleUI.ShowSectionHeader("DEMO 5: Interactive Hash Explorer");
            ConsoleUI.ShowInfo("  Type a password and press Enter to hash it. Type 'back' to return.\n");

            var hasher = new EnhancedMD5Hasher();
            while (true)
            {
                Console.Write("  Password > ");
                string input = Console.ReadLine()?.Trim() ?? "";
                if (input.ToLower() == "back") break;
                if (string.IsNullOrEmpty(input)) { ConsoleUI.ShowError("  Password cannot be empty."); continue; }

                var r = hasher.HashPasswordWithDetails(input);
                ConsoleUI.ShowQuickHash(r);
            }
        }

        // ──────────────────────────────────────────────
        // DEMO 6 – Change a user's password
        // ──────────────────────────────────────────────
        static void DemoChangePassword()
        {
            ConsoleUI.ShowSectionHeader("DEMO 6: Change Password");
            ConsoleUI.ShowInfo("  This demo uses sample users: alice, bob, charlie.\n");

            var authSystem = new AuthenticationSystem();
            authSystem.Register("alice", "Alice@2024!");
            authSystem.Register("bob", "Bobby#Secure99");
            authSystem.Register("charlie", "Charlie$Pass!");

            Console.Write("  Username: ");
            string username = Console.ReadLine()?.Trim() ?? "";
            Console.Write("  Current password: ");
            string currentPassword = Console.ReadLine() ?? "";
            Console.Write("  New password: ");
            string newPassword = Console.ReadLine() ?? "";
            Console.Write("  Confirm new password: ");
            string confirmPassword = Console.ReadLine() ?? "";

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(currentPassword) || string.IsNullOrEmpty(newPassword))
            {
                ConsoleUI.ShowError("  Username and passwords cannot be empty.");
                ConsoleUI.Pause();
                return;
            }

            if (newPassword != confirmPassword)
            {
                ConsoleUI.ShowError("  New password and confirmation do not match.");
                ConsoleUI.Pause();
                return;
            }

            bool changed = authSystem.ChangePassword(username, currentPassword, newPassword);
            if (changed)
                ConsoleUI.ShowSuccess($"  Password for '{username}' was changed successfully.");
            else
                ConsoleUI.ShowError($"  Failed to change password for '{username}'. Check username or current password.");

            ConsoleUI.Pause();
        }
    }
}
