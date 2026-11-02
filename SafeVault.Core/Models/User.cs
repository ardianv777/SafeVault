namespace SafeVault.Core.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User"; // "Admin", "User", "Auditor"
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public ICollection<VaultItem> VaultItems { get; set; } = new List<VaultItem>();
}
