namespace SafeVault.Core.Models;

public class VaultItem
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string Category { get; set; } = "General"; // "Credentials", "Notes", "Financial", "General"
    public bool IsEncrypted { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}
