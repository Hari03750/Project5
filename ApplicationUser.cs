using Microsoft.AspNetCore.Identity;

namespace SafeVault.Models;

// Extends ASP.NET Core Identity's built-in user so we get secure password
// hashing, lockout, and token support for free instead of hand-rolling auth.
public class ApplicationUser : IdentityUser
{
    public string DisplayName { get; set; } = string.Empty;
}
