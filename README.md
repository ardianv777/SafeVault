# SafeVault - Secure Backend Application & Security Verification

[![.NET 8.0](https://img.shields.io/badge/.NET-8.0-blue.svg)](https://dotnet.microsoft.com/)
[![Security Standards](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Hardened-green.svg)](https://owasp.org/)
[![Tests](https://img.shields.io/badge/xUnit-14%20Passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)]()

> **Microsoft Full-Stack Software Developer Professional Certificate**  
> **Course 8: Security and Authentication – Capstone Project Submission**

---

## 🛡️ Project Overview

**SafeVault** is a security-hardened backend web application developed with **ASP.NET Core (.NET 8)** designed for storing, managing, and retrieving highly sensitive digital assets (confidential notes, credentials, and financial records). 

This project integrates three structured security engineering activities completed with the pair-programming assistance of **Microsoft Copilot**:
1. **Activity 1:** Generating secure code for input validation and SQL injection prevention.
2. **Activity 2:** Implementing authentication and Role-Based Access Control (RBAC) using JWT tokens.
3. **Activity 3:** Debugging, reproducing, and resolving critical security vulnerabilities (SQL Injection and Cross-Site Scripting).

---

## 🏛️ System Architecture

The solution follows clean architectural separation across four modular projects:

```
SafeVault/
├── SafeVault.Core/          # Domain models, DTOs, allow-list validators & cryptographic services
│   ├── DTOs/                # Strongly-typed input contracts with validation attributes
│   ├── Models/              # User and VaultItem entities
│   └── Security/            # InputValidator (Regex/HTML encoding) & PasswordHasher (PBKDF2)
├── SafeVault.Data/          # Entity Framework Core DbContext and secure data repositories
│   ├── Repositories/        # IVaultRepository & VaultRepository (Parameterized Queries)
│   └── SafeVaultDbContext.cs
├── SafeVault.Web/           # ASP.NET Core Web API with secure middleware pipeline
│   ├── Controllers/         # AuthController, VaultController, AdminController
│   ├── Services/            # ITokenService & TokenService (JWT Generation)
│   ├── Program.cs           # Strict TokenValidationParameters & RBAC Policies
│   └── appsettings.json
├── SafeVault.Tests/         # Automated security and regression test suite (xUnit)
│   ├── SqlInjectionSecurityTests.cs
│   ├── XssProtectionSecurityTests.cs
│   ├── AuthenticationSecurityTests.cs
│   └── AuthorizationRbacSecurityTests.cs
└── SafeVault.sln
```

---

## 🔒 Key Security Features Implemented

### 1. Defensive Input Validation & SQL Injection Elimination
- **Allow-List Filtering:** User inputs are validated against strict regular expression patterns (`^[a-zA-Z0-9_\-\.]+$`), rejecting SQL control meta-characters (`'`, `"`, `--`, `;`).
- **Parameterized LINQ Queries:** Completely replaced legacy dynamic SQL string concatenation with Entity Framework Core parameterized query execution, ensuring input values are treated purely as literal values by the SQL engine.

### 2. Cryptographic Password Hashing & Safe Authentication
- **PBKDF2 with HMAC-SHA256:** Passwords are never stored in plaintext. They are salted using a 128-bit cryptographically secure pseudorandom salt generated via `RandomNumberGenerator` and hashed over **100,000 iterations**.
- **Timing Attack Mitigation:** Password verification uses `CryptographicOperations.FixedTimeEquals` to prevent side-channel timing analysis.

### 3. Stateless Token Authentication & Role-Based Access Control (RBAC)
- **JSON Web Tokens (JWT):** Issued upon successful credential verification with an expiration lifetime and signed using `HmacSha256`.
- **Strict Validation Parameters:** Configured with `ClockSkew = TimeSpan.Zero`, eliminating the default 5-minute leeway window, and strictly validating `Issuer`, `Audience`, and `SigningKey`.
- **RBAC Segmentation:**
  - `[Authorize(Roles = "User,Admin")]` restricts vault CRUD actions to authenticated item owners.
  - `[Authorize(Roles = "Admin")]` locks administrative audit consoles exclusively to administrators.
  - Multi-tenant isolation ensures User A cannot view, modify, or delete User B's vault items.

### 4. Cross-Site Scripting (XSS) Defenses
- **HTML Encoding:** All stored content and note descriptions undergo `HtmlEncoder.Default.Encode()` prior to serialization and storage.
- **Tag Stripping:** Note titles are stripped of opening/closing HTML tags via `InputValidator.StripHtmlTags`.
- **HTTP Security Headers:** Implemented defense-in-depth headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Content-Security-Policy: default-src 'self'`

---

## 🤖 Microsoft Copilot Pair-Programming Prompts

During the development and remediation phases, Microsoft Copilot was utilized as a cyber-security advisor:

| Activity | Engineering Goal | Exact Copilot Prompt Used |
| :--- | :--- | :--- |
| **Activity 1** | Input Validation | *"Generate a secure input validation helper in C# using allow-list regular expressions to validate usernames, email addresses, and text notes, preventing special characters used in script injection."* |
| **Activity 1** | SQLi Prevention | *"Refactor this repository search query from raw dynamic string interpolation to parameterized LINQ with Entity Framework Core to eliminate SQL injection vulnerabilities."* |
| **Activity 2** | Password Hashing | *"Implement PBKDF2 password hashing in C# with HMAC-SHA256, 100,000 iterations, 128-bit random salt, and constant-time string verification to prevent timing attacks."* |
| **Activity 2** | JWT & RBAC | *"Generate Program.cs configuration for JWT Bearer authentication with TokenValidationParameters requiring Issuer, Audience, Lifetime, and ClockSkew set to zero, and configure RBAC roles for Admin and User."* |
| **Activity 3** | Debugging Vulnerabilities | *"Analyze this controller method handling user notes. Identify potential stored XSS and authorization bypass vectors, and suggest remediation using HtmlEncoder and role authorization attributes."* |
| **Testing** | Security Unit Tests | *"Write xUnit unit tests verifying that SQL injection payloads like '' OR '1'='1' and ' UNION SELECT' do not bypass search filters or return unauthorized records."* |

---

## 🧪 Security Test Execution

The project includes 14 automated unit and security tests in `SafeVault.Tests`:

```bash
# Execute test suite
dotnet test SafeVault.sln --logger "console;verbosity=detailed"
```

### Test Suite Summary:
- **`SqlInjectionSecurityTests`** (5 tests): Validates safe search behavior and confirms payloads (`' OR 1=1 --`, `UNION SELECT`, `DROP TABLE`) cannot bypass tenant boundaries.
- **`XssProtectionSecurityTests`** (3 tests): Verifies HTML entity encoding of `<script>`, `<img onerror>`, and `<svg onload>` payloads.
- **`AuthenticationSecurityTests`** (4 tests): Tests PBKDF2 salting uniqueness, correct password validation, incorrect password rejection, and JWT generation.
- **`AuthorizationRbacSecurityTests`** (2 tests): Tests role restriction on `AdminController` and tenant isolation preventing cross-account deletion.

```text
Passed!  - Failed: 0, Passed: 14, Skipped: 0, Total: 14, Duration: 1.2s
```

---

## 🚀 Getting Started

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Visual Studio 2022 / VS Code / JetBrains Rider

### Build & Run
```bash
# Clone repository
git clone https://github.com/<your-username>/SafeVault.git
cd SafeVault

# Restore dependencies & Build
dotnet restore
dotnet build

# Run Web API
cd SafeVault.Web
dotnet run
```

Access Swagger UI at `https://localhost:5001/swagger` or `http://localhost:5000/swagger`.
