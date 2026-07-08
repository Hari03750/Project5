using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

// A piece of data a user stores in the vault. Title/Notes are user-supplied
// text and are treated as untrusted everywhere they are stored, queried, or rendered.
public class VaultItem
{
    public int Id { get; set; }

    [Required]
    [StringLength(120, MinimumLength = 1)]
    public string Title { get; set; } = string.Empty;

    [StringLength(2000)]
    public string Notes { get; set; } = string.Empty;

    [Required]
    public string OwnerUserId { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
