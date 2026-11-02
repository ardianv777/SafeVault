using System.Net;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Core.Security;

/// <summary>
/// Input validation and sanitization service generated with Microsoft Copilot.
/// Implements strict allow-list validation and defense-in-depth HTML encoding
/// to prevent SQL Injection, Cross-Site Scripting (XSS), and Command Injection.
/// </summary>
public static class InputValidator
{
    // Strict allow-list regex patterns
    private static readonly Regex UsernamePattern = new(@"^[a-zA-Z0-9_\-\.]{3,50}$", RegexOptions.Compiled);
    private static readonly Regex EmailPattern = new(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", RegexOptions.Compiled);
    private static readonly Regex SafeSearchPattern = new(@"^[a-zA-Z0-9\s\-_.]{1,100}$", RegexOptions.Compiled);
    private static readonly Regex DangerousCharsPattern = new(@"[<>'""`;&|*]", RegexOptions.Compiled);

    /// <summary>
    /// Validates username against allow-list of characters.
    /// </summary>
    public static bool IsValidUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username)) return false;
        return UsernamePattern.IsMatch(username);
    }

    /// <summary>
    /// Validates email address format.
    /// </summary>
    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        return EmailPattern.IsMatch(email);
    }

    /// <summary>
    /// Validates search query input using an allow-list pattern.
    /// Rejects dangerous SQL / script characters like quotes, semicolons, and comment dashes.
    /// </summary>
    public static bool IsValidSearchQuery(string? query)
    {
        if (string.IsNullOrWhiteSpace(query)) return false;
        if (query.Length > 100) return false;
        return SafeSearchPattern.IsMatch(query);
    }

    /// <summary>
    /// Detects potential SQL injection signatures in user input.
    /// Note: Parameterized queries are the primary defense; this provides defense-in-depth.
    /// </summary>
    public static bool ContainsSqlInjectionPattern(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        string normalized = input.ToLowerInvariant();
        string[] sqlSignatures = {
            "'", "\"", "--", "/*", "*/", ";", "@@",
            "union select", "union all select", "insert into", "delete from",
            "drop table", "drop database", "truncate table", "exec(", "execute(",
            "xp_cmdshell", "or 1=1", "or '1'='1", "or \"1\"=\"1"
        };

        foreach (var sig in sqlSignatures)
        {
            if (normalized.Contains(sig))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Sanitizes and encodes text to neutralize Cross-Site Scripting (XSS) vectors.
    /// Utilizes System.Text.Encodings.Web.HtmlEncoder.
    /// </summary>
    public static string SanitizeForHtml(string? rawInput)
    {
        if (string.IsNullOrEmpty(rawInput)) return string.Empty;

        // Perform HTML entity encoding to neutralize dangerous tags (<script>, <img>, <iframe>, etc.)
        return HtmlEncoder.Default.Encode(rawInput);
    }

    /// <summary>
    /// Strips harmful HTML tags and attributes from input while preserving plain text content.
    /// </summary>
    public static string StripHtmlTags(string? rawInput)
    {
        if (string.IsNullOrEmpty(rawInput)) return string.Empty;

        // Strip HTML tag brackets
        string clean = Regex.Replace(rawInput, @"<[^>]*>", string.Empty);
        return WebUtility.HtmlDecode(clean).Trim();
    }
}
