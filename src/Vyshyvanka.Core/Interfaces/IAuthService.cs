using Vyshyvanka.Core.Models;

namespace Vyshyvanka.Core.Interfaces;

/// <summary>
/// Service for authentication operations.
/// </summary>
public interface IAuthService
{
    /// <summary>Authenticates a user with email and password.</summary>
    Task<AuthResult> LoginAsync(string email, string password, CancellationToken cancellationToken = default);

    /// <summary>Registers a new user with the built-in provider.</summary>
    Task<AuthResult> RegisterAsync(string email, string password, string? displayName = null,
        CancellationToken cancellationToken = default);

    /// <summary>Issues a new access token from a valid refresh token.</summary>
    Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>Validates an access token, returning true when it is valid and not expired.</summary>
    Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>Hashes a plain-text password for storage.</summary>
    string HashPassword(string password);

    /// <summary>Verifies a plain-text password against a stored hash.</summary>
    bool VerifyPassword(string password, string passwordHash);

    /// <summary>
    /// Unlocks a user account by resetting failed login attempts and lockout end time.
    /// </summary>
    Task UnlockAccountAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Changes a user's password. Requires the current password for verification.
    /// </summary>
    Task<(bool Success, string? ErrorMessage)> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of an authentication operation.
/// </summary>
public record AuthResult
{
    /// <summary>Whether the operation succeeded.</summary>
    public bool Success { get; init; }

    /// <summary>Issued access token when successful; otherwise null.</summary>
    public string? AccessToken { get; init; }

    /// <summary>Issued refresh token when successful; otherwise null.</summary>
    public string? RefreshToken { get; init; }

    /// <summary>UTC expiry time of the access token. Null on failure.</summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>The authenticated user when successful; otherwise null.</summary>
    public User? User { get; init; }

    /// <summary>Error message when the operation failed. Null on success.</summary>
    public string? ErrorMessage { get; init; }
}
