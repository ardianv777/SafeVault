using Microsoft.EntityFrameworkCore;
using SafeVault.Core.Models;
using SafeVault.Core.Security;

namespace SafeVault.Data.Repositories;

/// <summary>
/// Vault data access repository.
/// Remediated using Microsoft Copilot to eliminate SQL Injection and enforce strict tenant isolation.
/// </summary>
public class VaultRepository : IVaultRepository
{
    private readonly SafeVaultDbContext _context;

    public VaultRepository(SafeVaultDbContext context)
    {
        _context = context;
    }

    public async Task<User?> GetUserByIdAsync(int id)
    {
        return await _context.Users.FindAsync(id);
    }

    public async Task<User?> GetUserByUsernameOrEmailAsync(string identifier)
    {
        // Safe parameterized LINQ query preventing SQL injection
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Username == identifier || u.Email == identifier);
    }

    public async Task<User> CreateUserAsync(User user)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }

    public async Task<IEnumerable<User>> GetAllUsersAsync()
    {
        return await _context.Users.ToListAsync();
    }

    public async Task<VaultItem?> GetVaultItemByIdAsync(int id, int userId)
    {
        // Enforces tenant isolation: item must belong to requesting user
        return await _context.VaultItems
            .FirstOrDefaultAsync(v => v.Id == id && v.UserId == userId);
    }

    public async Task<IEnumerable<VaultItem>> GetVaultItemsByUserAsync(int userId)
    {
        return await _context.VaultItems
            .Where(v => v.UserId == userId)
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync();
    }

    /// <summary>
    /// Search vault items with security controls against SQL Injection.
    ///
    /// VULNERABLE LEGACY PATTERN (BEFORE):
    /// string rawSql = $"SELECT * FROM VaultItems WHERE UserId = {userId} AND Title LIKE '%{searchTerm}%'";
    /// var items = _context.VaultItems.FromSqlRaw(rawSql).ToList(); // Vulnerable to SQL injection!
    ///
    /// SECURE IMPLEMENTATION GENERATED WITH MICROSOFT COPILOT (AFTER):
    /// Uses allow-list validation and parameterized LINQ / EF Core queries.
    /// EF Core compiles LINQ Contains/Equals into parameterized SQL (@p0, @p1) preventing query manipulation.
    /// </summary>
    public async Task<IEnumerable<VaultItem>> SearchVaultItemsAsync(int userId, string searchTerm)
    {
        if (string.IsNullOrWhiteSpace(searchTerm))
        {
            return await GetVaultItemsByUserAsync(userId);
        }

        // Layer 1 Defense: Input validation check
        if (InputValidator.ContainsSqlInjectionPattern(searchTerm))
        {
            // Security event: Reject dangerous SQL syntax outright
            return Enumerable.Empty<VaultItem>();
        }

        // Layer 2 Defense: Parameterized LINQ execution (EF Core automatically parameterizes the search string)
        return await _context.VaultItems
            .Where(v => v.UserId == userId && (v.Title.Contains(searchTerm) || v.Content.Contains(searchTerm)))
            .OrderByDescending(v => v.CreatedAt)
            .ToListAsync();
    }

    public async Task<VaultItem> CreateVaultItemAsync(VaultItem item)
    {
        item.CreatedAt = DateTime.UtcNow;
        item.UpdatedAt = DateTime.UtcNow;

        _context.VaultItems.Add(item);
        await _context.SaveChangesAsync();
        return item;
    }

    public async Task<bool> UpdateVaultItemAsync(VaultItem item)
    {
        var existing = await _context.VaultItems
            .FirstOrDefaultAsync(v => v.Id == item.Id && v.UserId == item.UserId);

        if (existing == null) return false;

        existing.Title = item.Title;
        existing.Content = item.Content;
        existing.Category = item.Category;
        existing.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteVaultItemAsync(int id, int userId)
    {
        var item = await _context.VaultItems
            .FirstOrDefaultAsync(v => v.Id == id && v.UserId == userId);

        if (item == null) return false;

        _context.VaultItems.Remove(item);
        await _context.SaveChangesAsync();
        return true;
    }
}
