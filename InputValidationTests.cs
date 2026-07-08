using SafeVault.Validation;
using Xunit;

namespace SafeVault.Tests;

public class InputValidationTests
{
    [Theory]
    [InlineData("john_doe")]
    [InlineData("jane.smith-99")]
    [InlineData("abc")]
    public void ValidUsernames_AreAccepted(string username)
    {
        Assert.True(InputValidator.IsValidUsername(username));
    }

    [Theory]
    [InlineData("ab")]                     // too short
    [InlineData("")]                       // empty
    [InlineData("john doe")]               // space not allowed
    [InlineData("john'--")]                // SQL injection attempt
    [InlineData("<script>alert(1)</script>")] // XSS attempt
    public void InvalidUsernames_AreRejected(string username)
    {
        Assert.False(InputValidator.IsValidUsername(username));
    }

    [Theory]
    [InlineData("user@example.com")]
    [InlineData("first.last@sub.example.co.uk")]
    public void ValidEmails_AreAccepted(string email)
    {
        Assert.True(InputValidator.IsValidEmail(email));
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("missing@domain")]
    [InlineData("")]
    public void InvalidEmails_AreRejected(string email)
    {
        Assert.False(InputValidator.IsValidEmail(email));
    }

    [Theory]
    [InlineData("Str0ng!Pass")]
    [InlineData("C0mplex#Passw0rd")]
    public void StrongPasswords_AreAccepted(string password)
    {
        Assert.True(InputValidator.IsStrongPassword(password));
    }

    [Theory]
    [InlineData("short1!")]        // too short
    [InlineData("alllowercase1!")] // no uppercase
    [InlineData("ALLUPPERCASE1!")] // no lowercase
    [InlineData("NoDigitsHere!")]  // no digit
    [InlineData("NoSymbols123")]   // no symbol
    public void WeakPasswords_AreRejected(string password)
    {
        Assert.False(InputValidator.IsStrongPassword(password));
    }

    [Theory]
    [InlineData("'; DROP TABLE Users; --")]
    [InlineData("1 OR 1=1")]
    [InlineData("admin' UNION SELECT * FROM AspNetUsers --")]
    public void SuspiciousSqlPatterns_AreDetected(string input)
    {
        Assert.True(InputValidator.ContainsSuspiciousSqlPattern(input));
    }

    [Theory]
    [InlineData("My grocery list")]
    [InlineData("Meeting notes for Q3 planning")]
    public void OrdinaryText_IsNotFlaggedAsSuspicious(string input)
    {
        Assert.False(InputValidator.ContainsSuspiciousSqlPattern(input));
    }

    [Fact]
    public void SanitizeHtml_StripsScriptTags()
    {
        var result = InputValidator.SanitizeHtml("<script>alert('xss')</script>Hello");
        Assert.DoesNotContain("<script", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Hello", result);
    }

    [Fact]
    public void SanitizeHtml_StripsEventHandlerAttributes()
    {
        var result = InputValidator.SanitizeHtml("<img src=x onerror=\"alert(1)\">");
        Assert.DoesNotContain("onerror", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsValidFreeText_RejectsOverLongInput()
    {
        var tooLong = new string('a', 3000);
        Assert.False(InputValidator.IsValidFreeText(tooLong, 2000));
    }

    [Fact]
    public void IsValidFreeText_RejectsSqlInjectionAttempt()
    {
        Assert.False(InputValidator.IsValidFreeText("'; DROP TABLE VaultItems; --", 2000));
    }
}
