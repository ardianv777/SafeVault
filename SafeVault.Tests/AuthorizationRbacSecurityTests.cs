using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using SafeVault.Core.Models;
using SafeVault.Data.Repositories;
using SafeVault.Web.Controllers;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Security Verification Tests for Role-Based Access Control (RBAC) and Tenant Isolation.
/// Verifies that unauthorized roles cannot access sensitive endpoints.
/// </summary>
public class AuthorizationRbacSecurityTests
{
    private static ControllerContext CreateControllerContextWithClaims(int userId, string username, string role)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Name, username),
            new(ClaimTypes.Role, role)
        };
        var identity = new ClaimsIdentity(claims, "TestAuthType");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        return new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    [Fact]
    public void AdminController_HasAuthorizeAttributeRestrictedToAdmin()
    {
        // Act
        var authAttributes = typeof(AdminController)
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .ToList();

        // Assert: Must enforce [Authorize(Roles = "Admin")]
        Assert.NotEmpty(authAttributes);
        Assert.Equal("Admin", authAttributes.First().Roles);
    }

    [Fact]
    public void VaultController_HasAuthorizeAttributeEnforced()
    {
        // Act
        var authAttributes = typeof(VaultController)
            .GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
            .Cast<AuthorizeAttribute>()
            .ToList();

        // Assert: Entire controller must require authenticated requests
        Assert.NotEmpty(authAttributes);
    }

    [Fact]
    public async Task AdminController_WhenAccessedByAdmin_ReturnsAllUsers()
    {
        // Arrange
        var mockRepo = new Mock<IVaultRepository>();
        mockRepo.Setup(r => r.GetAllUsersAsync())
            .ReturnsAsync(new List<User>
            {
                new() { Id = 1, Username = "admin", Role = "Admin" },
                new() { Id = 2, Username = "user1", Role = "User" }
            });

        var mockLogger = new Mock<ILogger<AdminController>>();
        var controller = new AdminController(mockRepo.Object, mockLogger.Object)
        {
            ControllerContext = CreateControllerContextWithClaims(1, "admin", "Admin")
        };

        // Act
        var result = await controller.GetAllUsers();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(okResult.Value);
    }

    [Fact]
    public async Task VaultController_TenantIsolation_CannotDeleteOtherUsersItem()
    {
        // Arrange: User 1 tries to delete Item 99 which belongs to User 2
        var mockRepo = new Mock<IVaultRepository>();
        mockRepo.Setup(r => r.DeleteVaultItemAsync(99, 1))
            .ReturnsAsync(false); // Repository returns false because userId does not match

        var mockLogger = new Mock<ILogger<VaultController>>();
        var controller = new VaultController(mockRepo.Object, mockLogger.Object)
        {
            ControllerContext = CreateControllerContextWithClaims(1, "user1", "User")
        };

        // Act
        var result = await controller.DeleteVaultItem(99);

        // Assert: User 1 is blocked with NotFound / Unauthorized
        Assert.IsType<NotFoundObjectResult>(result);
    }
}
