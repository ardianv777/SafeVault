using SafeVault.Core.Models;

namespace SafeVault.Web.Services;

public interface ITokenService
{
    string GenerateToken(User user);
}
