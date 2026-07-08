using System.ComponentModel.DataAnnotations;

namespace SafeVault.DTOs;

public class RegisterRequest
{
    [Required, StringLength(32, MinimumLength = 3)]
    public string UserName { get; set; } = string.Empty;

    [Required, EmailAddress, StringLength(254)]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(128, MinimumLength = 8)]
    public string Password { get; set; } = string.Empty;

    [Required, StringLength(100, MinimumLength = 1)]
    public string DisplayName { get; set; } = string.Empty;
}
