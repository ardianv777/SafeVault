using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Models;
using SafeVault.Core.Security;
using SafeVault.Data;
using SafeVault.Data.Repositories;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Security Verification Tests for SQL Injection Prevention.
/// Generated and refined using Microsoft Copilot to test OWASP Top 10 Injection vulnerabilities.
/// </summary>
public class SqlInjectionSecurityTests
{
    private SafeVaultDbContext GetInMemoryDbContext(string dbName)
    {
        var options = new DbContextOptionsBuilder<SafeVaultDbContext>()
            .UseInMemoryDatabase(databaseName: dbName)
            .Options;

        var context = new SafeVaultDbContext(options);
        context.Database.EnsureDeleted();
        context.Database.EnsureCreated();

        // Seed Users
        var user1 = new User { Id = 1, Username = "alice", Email = "alice@example.com", PasswordHash = "hash1", Role = "User" };
        var user2 = new User { Id = 2, Username = "bob", Email = "bob@example.com", PasswordHash = "hash2", Role = "User" };
        var admin = new User { Id = 3, Username = "admin", Email = "admin@example.com", PasswordHash = "hash3", Role = "Admin" };
        context.Users.AddRange(user1, user2, admin);

        // Seed Vault Items
        context.VaultItems.AddRange(
            new VaultItem { Id = 1, UserId = 1, Title = "Alice Secret Project", Content = "Confidential design plans", Category = "Notes" },
            new VaultItem { Id = 2, UserId = 1, Title = "Alice Banking PIN", Content = "9876", Category = "Financial" },
            new VaultItem { Id = 3, UserId = 2, Title = "Bob Secret Recipe", Content = "Secret sauce formula", Category = "Notes" },
            new VaultItem { Id = 4, UserId = 3, Title = "Admin Master Credentials", Content = "Root access key", Category = "Credentials" }
        );

        context.SaveChanges();
        return context;
    }

    [Fact]
    public async Task SearchVaultItems_NormalQuery_ReturnsOnlyMatchingUserItems()
    {
        // Arrange
        using var context = GetInMemoryDbContext("NormalSearchDb");
        var repository = new VaultRepository(context);

        // Act
        var results = await repository.SearchVaultItemsAsync(userId: 1, searchTerm: "Secret");

        // Assert: Alice should only see her own item matching "Secret"
        Assert.Single(results);
        Assert.Equal("Alice Secret Project", results.First().Title);
        Assert.Equal(1, results.First().UserId);
    }

    [Theory]
    [InlineData("' OR '1'='1")]
    [InlineData("' OR 1=1 --")]
    [InlineData("admin'--")]
    [InlineData("' UNION SELECT * FROM Users --")]
    [InlineData("'; DROP TABLE VaultItems; --")]
    public async Task SearchVaultItems_SqlInjectionPayloads_DoNotLeakOtherUsersData(string maliciousPayload)
    {
        // Arrange
        using var context = GetInMemoryDbContext("SqlInjectionDb_" + Guid.NewGuid());
        var repository = new VaultRepository(context);

        // Act: Attacker (User 1) inputs SQL injection payloads to extract Bob or Admin data
        var results = await repository.SearchVaultItemsAsync(userId: 1, searchTerm: maliciousPayload);

        // Assert: Must not return Bob's or Admin's items, and query must not crash
        Assert.DoesNotContain(results, item => item.UserId == 2);
        Assert.DoesNotContain(results, item => item.UserId == 3);
        Assert.DoesNotContain(results, item => item.Title.Contains("Bob") || item.Title.Contains("Admin"));
    }

    [Theory]
    [InlineData("' OR 1=1 --")]
    [InlineData("'; EXEC xp_cmdshell('dir'); --")]
    [InlineData("1' UNION ALL SELECT NULL, NULL, NULL, NULL --")]
    public void InputValidator_ContainsSqlInjectionPattern_DetectsMaliciousSignatures(string injectionString)
    {
        // Act
        bool isDetected = InputValidator.ContainsSqlInjectionPattern(injectionString);

        // Assert
        Assert.True(isDetected, $"Expected pattern to be flagged as SQL injection: {injectionString}");
    }

    [Theory]
    [InlineData("ProjectPlan")]
    [InlineData("Meeting Notes 2026")]
    [InlineData("Financial_Q3")]
    public void InputValidator_IsValidSearchQuery_AcceptsSafeAllowListedInput(string safeQuery)
    {
        // Act
        bool isValid = InputValidator.IsValidSearchQuery(safeQuery);

        // Assert
        Assert.True(isValid);
    }
}
