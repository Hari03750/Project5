using System.ComponentModel.DataAnnotations;

namespace SafeVault.DTOs;

public class VaultItemRequest
{
    [Required, StringLength(120, MinimumLength = 1)]
    public string Title { get; set; } = string.Empty;

    [StringLength(2000)]
    public string Notes { get; set; } = string.Empty;
}
