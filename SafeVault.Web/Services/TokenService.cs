using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Core.Models;

namespace SafeVault.Web.Services;

/// <summary>
/// JWT token generation service built with Microsoft Copilot.
/// Implements Role-Based Access Control (RBAC) claims and HMAC-SHA256 signature.
/// </summary>
public class TokenService : ITokenService
{
    private readonly IConfiguration _config;

    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    public string GenerateToken(User user)
    {
        var secretKey = _config["Jwt:Key"] ?? "SafeVaultSuperSecretKey2026!MustBeAtLeast32BytesLong!";
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, user.Role), // RBAC Role claim ("Admin", "User", "Auditor")
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["Jwt:DurationInMinutes"] ?? "60")),
            Issuer = _config["Jwt:Issuer"] ?? "SafeVaultAPI",
            Audience = _config["Jwt:Audience"] ?? "SafeVaultClients",
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
