using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data.Repositories;

namespace SafeVault.Web.Controllers;

/// <summary>
/// Administrative Controller secured with Role-Based Access Control (RBAC).
/// Restricted exclusively to users possessing the 'Admin' role claim.
/// Non-admin requests will be rejected with HTTP 403 Forbidden.
/// </summary>
[Authorize(Roles = "Admin")]
[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    private readonly IVaultRepository _repository;
    private readonly ILogger<AdminController> _logger;

    public AdminController(IVaultRepository repository, ILogger<AdminController> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    /// <summary>
    /// Gets all registered users. Restricted to Admin role.
    /// </summary>
    [HttpGet("users")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _repository.GetAllUsersAsync();
        var result = users.Select(u => new
        {
            u.Id,
            u.Username,
            u.Email,
            u.Role,
            u.CreatedAt
        });

        _logger.LogInformation("Admin access: User list retrieved by Admin {AdminName}", User.Identity?.Name);
        return Ok(result);
    }

    /// <summary>
    /// Security audit summary endpoint. Restricted to Admin role.
    /// </summary>
    [HttpGet("audit-summary")]
    public IActionResult GetAuditSummary()
    {
        return Ok(new
        {
            status = "Secure",
            sqlInjectionProtection = "Enabled (Parameterized Queries + Input Allow-list)",
            xssProtection = "Enabled (HTML Encoding + Tag Stripping)",
            authentication = "JWT Bearer (HMAC-SHA256, 60min expiry)",
            rbacEnforcement = "Active (Admin, User, Auditor roles)",
            dataProtection = "PBKDF2 Password Hashing (100,000 iterations)"
        });
    }
}
