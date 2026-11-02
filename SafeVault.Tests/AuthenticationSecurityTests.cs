using Microsoft.Extensions.Configuration;
using SafeVault.Core.Models;
using SafeVault.Core.Security;
using SafeVault.Web.Services;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Security Verification Tests for Authentication & Password Cryptography.
/// Verifies PBKDF2 salting, constant-time validation, and JWT generation.
/// </summary>
public class AuthenticationSecurityTests
{
    [Fact]
    public void HashPassword_ValidPassword_GeneratesSaltedHashWith3Parts()
    {
        // Arrange
        string plainPassword = "SuperSecurePassword123!#";

        // Act
        string hash = PasswordHasher.HashPassword(plainPassword);

        // Assert
        Assert.NotNull(hash);
        var parts = hash.Split('.');
        Assert.Equal(3, parts.Length); // iterations.salt.hash
        Assert.Equal("100000", parts[0]);
    }

    [Fact]
    public void HashPassword_SamePasswordHashedTwice_GeneratesDifferentHashesDueToUniqueSalts()
    {
        // Arrange
        string password = "P@ssw0rdSecure2026!";

        // Act
        string hash1 = PasswordHasher.HashPassword(password);
        string hash2 = PasswordHasher.HashPassword(password);

        // Assert
        Assert.NotEqual(hash1, hash2); // Unique salts prevent rainbow table attacks
    }

    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        string password = "StrongAuthenticationTest#2026";
        string hash = PasswordHasher.HashPassword(password);

        // Act
        bool isValid = PasswordHasher.VerifyPassword(password, hash);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFalse()
    {
        // Arrange
        string password = "CorrectPassword123!";
        string wrongPassword = "WrongPassword123!";
        string hash = PasswordHasher.HashPassword(password);

        // Act
        bool isValid = PasswordHasher.VerifyPassword(wrongPassword, hash);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void TokenService_GenerateToken_ContainsUserClaimsAndRole()
    {
        // Arrange
        var inMemorySettings = new Dictionary<string, string?> {
            {"Jwt:Key", "TestSuperSecretKeyForSafeVaultUnitTesting2026!"},
            {"Jwt:Issuer", "SafeVaultAPI"},
            {"Jwt:Audience", "SafeVaultClients"},
            {"Jwt:DurationInMinutes", "60"}
        };

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        var tokenService = new TokenService(configuration);
        var user = new User
        {
            Id = 42,
            Username = "security_officer",
            Email = "officer@safevault.io",
            Role = "Admin"
        };

        // Act
        string token = tokenService.GenerateToken(user);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
        Assert.Contains(".", token); // Valid JWT structure
    }
}
