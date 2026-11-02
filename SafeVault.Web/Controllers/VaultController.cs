using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Core.DTOs;
using SafeVault.Core.Models;
using SafeVault.Core.Security;
using SafeVault.Data.Repositories;

namespace SafeVault.Web.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class VaultController : ControllerBase
{
    private readonly IVaultRepository _repository;
    private readonly ILogger<VaultController> _logger;

    public VaultController(IVaultRepository repository, ILogger<VaultController> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    private int GetCurrentUserId()
    {
        var idClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (int.TryParse(idClaim, out int userId))
            return userId;

        throw new UnauthorizedAccessException("Invalid user identity in token.");
    }

    /// <summary>
    /// Gets all vault items for the authenticated user.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> GetMyVaultItems()
    {
        int userId = GetCurrentUserId();
        var items = await _repository.GetVaultItemsByUserAsync(userId);

        var response = items.Select(item => new VaultItemResponseDto
        {
            Id = item.Id,
            UserId = item.UserId,
            Title = InputValidator.SanitizeForHtml(item.Title),
            Content = InputValidator.SanitizeForHtml(item.Content),
            Category = item.Category,
            CreatedAt = item.CreatedAt,
            UpdatedAt = item.UpdatedAt
        });

        return Ok(response);
    }

    /// <summary>
    /// Searches vault items using parameterized query logic.
    /// Defends against SQL injection attacks.
    /// </summary>
    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string query)
    {
        int userId = GetCurrentUserId();

        if (string.IsNullOrWhiteSpace(query))
        {
            return BadRequest(new { message = "Search query cannot be empty." });
        }

        // Layer 1 Defense: Reject queries containing SQL injection signatures
        if (InputValidator.ContainsSqlInjectionPattern(query))
        {
            _logger.LogWarning("Security Alert: SQL Injection attempt blocked for UserId={UserId}, Payload={Payload}", userId, query);
            return BadRequest(new { message = "Invalid characters detected in search query." });
        }

        // Layer 2 Defense: Parameterized search via repository
        var results = await _repository.SearchVaultItemsAsync(userId, query);

        var sanitized = results.Select(item => new VaultItemResponseDto
        {
            Id = item.Id,
            UserId = item.UserId,
            Title = InputValidator.SanitizeForHtml(item.Title),
            Content = InputValidator.SanitizeForHtml(item.Content),
            Category = item.Category,
            CreatedAt = item.CreatedAt,
            UpdatedAt = item.UpdatedAt
        });

        return Ok(sanitized);
    }

    /// <summary>
    /// Creates a new vault item with XSS sanitization and input validation.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CreateVaultItem([FromBody] CreateVaultItemDto dto)
    {
        int userId = GetCurrentUserId();

        // XSS Defense: Sanitize and encode user input before storage
        string cleanTitle = InputValidator.StripHtmlTags(dto.Title);
        string sanitizedContent = InputValidator.SanitizeForHtml(dto.Content);

        var item = new VaultItem
        {
            UserId = userId,
            Title = cleanTitle,
            Content = sanitizedContent,
            Category = dto.Category,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        var created = await _repository.CreateVaultItemAsync(item);

        return CreatedAtAction(nameof(GetMyVaultItems), new { id = created.Id }, new VaultItemResponseDto
        {
            Id = created.Id,
            UserId = created.UserId,
            Title = created.Title,
            Content = created.Content,
            Category = created.Category,
            CreatedAt = created.CreatedAt,
            UpdatedAt = created.UpdatedAt
        });
    }

    /// <summary>
    /// Deletes a vault item ensuring tenant isolation (cannot delete other users' items).
    /// </summary>
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> DeleteVaultItem(int id)
    {
        int userId = GetCurrentUserId();
        bool deleted = await _repository.DeleteVaultItemAsync(id, userId);

        if (!deleted)
        {
            return NotFound(new { message = "Vault item not found or unauthorized." });
        }

        return Ok(new { success = true, message = "Vault item deleted successfully." });
    }
}
