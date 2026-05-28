# Enhanced MD5 Authentication System
### Salting · Peppering · Iterative Strengthening

---

## Quick Start (Visual Studio)

1. **Open** `EnhancedMD5Auth.sln` in **Visual Studio 2022** (or later).
2. Press **F5** (or Ctrl+F5 for no-debugger) — no NuGet restore needed.
3. The console menu will appear.

> Requires **.NET 8 SDK** (ships with VS 2022 v17.8+).  
> Target Framework: `net8.0`

---

## Quick Start (Command Line)

```bash
cd EnhancedMD5Auth
dotnet run
```

---

## Project Structure

```
EnhancedMD5Auth.sln
└── EnhancedMD5Auth/
    ├── EnhancedMD5Auth.csproj
    ├── Program.cs                  ← entry point / demo runner
    ├── Core/
    │   ├── EnhancedMD5Hasher.cs    ← full hashing pipeline
    │   ├── AuthenticationSystem.cs ← simulated user store
    │   └── HashingUtils.cs         ← plain MD5, secure compare, entropy
    └── UI/
        └── ConsoleUI.cs            ← all rendering / colour output
```

---

## Hashing Pipeline

```
password
    │
    ▼
password + SALT  (128-bit cryptographic random per password)
    │
    ▼
password + salt + PEPPER  (server-side secret, never in DB)
    │
    ▼
MD5( peppered string )
    │
    ▼ × 10 000 iterations
MD5( hash + salt )  ──► FINAL HASH  (stored in DB alongside salt + iteration count)
```

### What is stored in the database?

| Column     | Example value                        |
|------------|--------------------------------------|
| username   | alice                                |
| salt       | 3f8a1c...  (32 hex chars, 16 bytes) |
| iterations | 10000                                |
| hash       | 7b2e4f...  (32 hex chars)           |

The **pepper** and the **plaintext password** are **never** stored.

---

## Demo Screens

| Option | What you see |
|--------|-------------|
| **1 – Hashing Pipeline** | Every intermediate value: salt, pepper concat, first MD5, final hash after N iterations |
| **2 – Registration & Login** | Three users registered; correct / wrong / unknown-user logins tested |
| **3 – Attack Resistance** | Same password → 5 different hashes; rainbow-table comparison; constant-time compare |
| **4 – Benchmark** | Hash time for 100 → 100 000 iterations with security rating |
| **5 – Interactive** | Type any password and see its hash + strength in real time |

---

## Security Notes

| Threat | Defence applied |
|--------|----------------|
| Rainbow table | Unique random salt per password |
| Database theft | Pepper stored outside DB |
| Brute-force | 10 000 iterations key-stretching |
| Timing attack | Constant-time `SecureCompare` |
| Weak password | Shannon entropy estimator + label |

> **Production advice:** For new systems prefer **Argon2id** (memory-hard) or  
> **bcrypt** over MD5. This project shows *why* salting/peppering/stretching  
> matter — the same principles apply to any underlying hash function.

---

## Requirements

- Visual Studio 2022 17.8+ **or** .NET 8 SDK
- Windows / macOS / Linux (console colours work on all three)
- No NuGet packages — uses only `System.Security.Cryptography` from BCL
