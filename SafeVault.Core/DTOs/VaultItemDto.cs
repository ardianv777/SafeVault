using System.ComponentModel.DataAnnotations;

namespace SafeVault.Core.DTOs;

public class CreateVaultItemDto
{
    [Required(ErrorMessage = "Title is required.")]
    [StringLength(100, MinimumLength = 1, ErrorMessage = "Title must be between 1 and 100 characters.")]
    [RegularExpression(@"^[a-zA-Z0-9\s\-_.,?!@#%&()]+$", ErrorMessage = "Title contains invalid characters.")]
    public string Title { get; set; } = string.Empty;

    [Required(ErrorMessage = "Content is required.")]
    [StringLength(5000, ErrorMessage = "Content cannot exceed 5000 characters.")]
    public string Content { get; set; } = string.Empty;

    [RegularExpression(@"^(Credentials|Notes|Financial|General)$", ErrorMessage = "Invalid category.")]
    public string Category { get; set; } = "General";
}

public class VaultItemResponseDto
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
