using System.ComponentModel.DataAnnotations;

namespace SafeVault.Core.DTOs;

public class LoginDto
{
    [Required(ErrorMessage = "Username or Email is required.")]
    [StringLength(100, ErrorMessage = "Username or Email cannot exceed 100 characters.")]
    public string UsernameOrEmail { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required.")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
    public string Password { get; set; } = string.Empty;
}
