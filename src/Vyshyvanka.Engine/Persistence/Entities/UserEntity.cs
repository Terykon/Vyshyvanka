using Vyshyvanka.Core.Enums;

namespace Vyshyvanka.Engine.Persistence.Entities;

/// <summary>
/// EF Core entity for user storage.
/// </summary>
public class UserEntity
{
    /// <summary>Unique identifier.</summary>
    public Guid Id { get; set; }

    /// <summary>User email address.</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>Display name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>Hashed password.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>User role.</summary>
    public UserRole Role { get; set; }

    /// <summary>Whether the user is active.</summary>
    public bool IsActive { get; set; }

    /// <summary>Creation timestamp.</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>Last login timestamp.</summary>
    public DateTime? LastLoginAt { get; set; }

    /// <summary>Refresh token for JWT authentication.</summary>
    public string? RefreshToken { get; set; }

    /// <summary>Refresh token expiry.</summary>
    public DateTime? RefreshTokenExpiresAt { get; set; }

    /// <summary>External subject identifier from an OIDC provider (null for built-in users).</summary>
    public string? ExternalId { get; set; }

    /// <summary>Number of consecutive failed login attempts.</summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>UTC time when the account lockout expires. Null means not locked.</summary>
    public DateTime? LockoutEnd { get; set; }

    /// <summary>Which authentication provider owns this user.</summary>
    public AuthenticationProvider AuthenticationProvider { get; set; }

    /// <summary>
    /// Indicates whether the user has changed their password from the initial seeded value.
    /// Used to determine if development credentials should still be shown on the login page.
    /// </summary>
    public bool HasChangedPassword { get; set; }

    /// <summary>API keys owned by this user.</summary>
    public List<ApiKeyEntity> ApiKeys { get; set; } = [];
}
