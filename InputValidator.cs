using System.Text.RegularExpressions;
using Ganss.Xss;

namespace SafeVault.Validation;

/// <summary>
/// Centralized, reusable input-validation and output-sanitization logic.
/// This is defense-in-depth: EF Core parameterization already prevents SQL
/// injection, and Razor/JSON encoding already escapes output, but validating
/// and sanitizing at the boundary catches malformed data early, reduces
/// stored-XSS risk, and gives predictable error messages to the client.
/// </summary>
public static class InputValidator
{
    private static readonly Regex UsernamePattern = new(
        @"^[a-zA-Z0-9_\.\-]{3,32}$", RegexOptions.Compiled);

    private static readonly Regex EmailPattern = new(
        @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

    // Rejects classic SQL-meta-character injection payloads as an extra
    // tripwire even though parameterized queries are the real defense.
    private static readonly Regex SqlSuspiciousPattern = new(
        @"(--|;|/\*|\*/|xp_|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b|\bupdate\b|\bexec\b)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly HtmlSanitizer Sanitizer = new();

    public static bool IsValidUsername(string? username) =>
        !string.IsNullOrWhiteSpace(username) && UsernamePattern.IsMatch(username);

    public static bool IsValidEmail(string? email) =>
        !string.IsNullOrWhiteSpace(email) && email.Length <= 254 && EmailPattern.IsMatch(email);

    public static bool IsStrongPassword(string? password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 8 || password.Length > 128)
        {
            return false;
        }

        bool hasUpper = password.Any(char.IsUpper);
        bool hasLower = password.Any(char.IsLower);
        bool hasDigit = password.Any(char.IsDigit);
        bool hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));

        return hasUpper && hasLower && hasDigit && hasSymbol;
    }

    /// <summary>
    /// Flags input that looks like a SQL-injection attempt. Used as an
    /// additional guard on free-text fields before they ever reach the
    /// data layer. Parameterized queries remain the primary defense.
    /// </summary>
    public static bool ContainsSuspiciousSqlPattern(string? input) =>
        !string.IsNullOrEmpty(input) && SqlSuspiciousPattern.IsMatch(input);

    /// <summary>
    /// Strips executable/markup content from free-text fields before they
    /// are persisted, so stored XSS cannot be introduced via saved data
    /// even if a future rendering path forgets to encode on output.
    /// </summary>
    public static string SanitizeHtml(string? input) =>
        string.IsNullOrEmpty(input) ? string.Empty : Sanitizer.Sanitize(input);

    public static bool IsValidFreeText(string? input, int maxLength)
    {
        if (input is null) return false;
        if (input.Length > maxLength) return false;
        return !ContainsSuspiciousSqlPattern(input);
    }
}
