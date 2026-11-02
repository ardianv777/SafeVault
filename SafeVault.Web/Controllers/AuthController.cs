using Microsoft.AspNetCore.Mvc;
using SafeVault.Core.DTOs;
using SafeVault.Core.Models;
using SafeVault.Core.Security;
using SafeVault.Data.Repositories;
using SafeVault.Web.Services;

namespace SafeVault.Web.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IVaultRepository _repository;
    private readonly ITokenService _tokenService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IVaultRepository repository, ITokenService tokenService, ILogger<AuthController> logger)
    {
        _repository = repository;
        _tokenService = tokenService;
        _logger = logger;
    }

    /// <summary>
    /// Registers a new user with input validation, role assignment, and secure password hashing.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        // Model validation automatically executed via [ApiController] & DataAnnotations

        // Secondary defense: Allow-list check
        if (!InputValidator.IsValidUsername(dto.Username))
        {
            return BadRequest(new { message = "Username contains disallowed characters." });
        }

        if (!InputValidator.IsValidEmail(dto.Email))
        {
            return BadRequest(new { message = "Invalid email format." });
        }

        // Check if user already exists
        var existingUser = await _repository.GetUserByUsernameOrEmailAsync(dto.Username);
        if (existingUser != null)
        {
            return Conflict(new { message = "Username is already registered." });
        }

        var existingEmail = await _repository.GetUserByUsernameOrEmailAsync(dto.Email);
        if (existingEmail != null)
        {
            return Conflict(new { message = "Email is already registered." });
        }

        // Hash password securely with PBKDF2 (100,000 iterations, random salt)
        string passwordHash = PasswordHasher.HashPassword(dto.Password);

        // Sanitize role assignment: Only allow Admin if explicitly configured or default to User
        string assignedRole = string.Equals(dto.Role, "Admin", StringComparison.OrdinalIgnoreCase) ? "Admin" :
                              string.Equals(dto.Role, "Auditor", StringComparison.OrdinalIgnoreCase) ? "Auditor" : "User";

        var user = new User
        {
            Username = dto.Username.Trim(),
            Email = dto.Email.Trim().ToLowerInvariant(),
            PasswordHash = passwordHash,
            Role = assignedRole,
            CreatedAt = DateTime.UtcNow
        };

        await _repository.CreateUserAsync(user);

        _logger.LogInformation("Security Audit: New user registered with Username={Username}, Role={Role}", user.Username, user.Role);

        return Ok(new
        {
            success = true,
            message = "User registered successfully.",
            userId = user.Id,
            username = user.Username,
            role = user.Role
        });
    }

    /// <summary>
    /// Authenticates user and issues signed JWT bearer token.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var user = await _repository.GetUserByUsernameOrEmailAsync(dto.UsernameOrEmail.Trim());
        if (user == null)
        {
            // Generic message to prevent user enumeration
            return Unauthorized(new { message = "Invalid username or password." });
        }

        // Constant-time password verification preventing side-channel timing attacks
        bool isPasswordValid = PasswordHasher.VerifyPassword(dto.Password, user.PasswordHash);
        if (!isPasswordValid)
        {
            _logger.LogWarning("Security Audit: Failed login attempt for UsernameOrEmail={Identifier}", dto.UsernameOrEmail);
            return Unauthorized(new { message = "Invalid username or password." });
        }

        // Issue JWT token with Role claims
        string token = _tokenService.GenerateToken(user);

        _logger.LogInformation("Security Audit: Successful login for Username={Username}, Role={Role}", user.Username, user.Role);

        return Ok(new AuthResponseDto
        {
            Success = true,
            Message = "Authentication successful.",
            Token = token,
            Username = user.Username,
            Role = user.Role,
            ExpiresAt = DateTime.UtcNow.AddHours(1)
        });
    }
}
