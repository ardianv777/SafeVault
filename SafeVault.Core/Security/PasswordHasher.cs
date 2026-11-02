using System.Security.Cryptography;

namespace SafeVault.Core.Security;

/// <summary>
/// Cryptographically secure password hasher implementing PBKDF2 with HMAC-SHA256,
/// 100,000 iterations, 128-bit random salt, and constant-time equality comparison.
/// Generated and validated with Microsoft Copilot following OWASP recommendations.
/// </summary>
public static class PasswordHasher
{
    private const int SaltSize = 16; // 128 bits
    private const int HashSize = 32; // 256 bits
    private const int Iterations = 100000;
    private static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA256;

    /// <summary>
    /// Hashes a plain-text password using PBKDF2 with salt.
    /// Format: {iterations}.{salt_base64}.{hash_base64}
    /// </summary>
    public static string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithm,
            HashSize);

        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Verifies a plain-text password against a stored hashed password string.
    /// Utilizes CryptographicOperations.FixedTimeEquals to prevent side-channel timing attacks.
    /// </summary>
    public static bool VerifyPassword(string password, string storedHash)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash))
            return false;

        string[] parts = storedHash.Split('.', 3);
        if (parts.Length != 3)
            return false;

        if (!int.TryParse(parts[0], out int iterations))
            return false;

        byte[] salt = Convert.FromBase64String(parts[1]);
        byte[] expectedHash = Convert.FromBase64String(parts[2]);

        byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithm,
            expectedHash.Length);

        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}
