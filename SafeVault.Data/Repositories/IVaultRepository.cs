using SafeVault.Core.Models;

namespace SafeVault.Data.Repositories;

public interface IVaultRepository
{
    Task<User?> GetUserByIdAsync(int id);
    Task<User?> GetUserByUsernameOrEmailAsync(string identifier);
    Task<User> CreateUserAsync(User user);
    Task<IEnumerable<User>> GetAllUsersAsync();

    Task<VaultItem?> GetVaultItemByIdAsync(int id, int userId);
    Task<IEnumerable<VaultItem>> GetVaultItemsByUserAsync(int userId);
    Task<IEnumerable<VaultItem>> SearchVaultItemsAsync(int userId, string searchTerm);
    Task<VaultItem> CreateVaultItemAsync(VaultItem item);
    Task<bool> UpdateVaultItemAsync(VaultItem item);
    Task<bool> DeleteVaultItemAsync(int id, int userId);
}
