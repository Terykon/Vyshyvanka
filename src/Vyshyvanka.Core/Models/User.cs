using Vyshyvanka.Core.Enums;

namespace Vyshyvanka.Core.Models;

/// <summary>
/// Represents a user in the system.
/// </summary>
public record User
{
    /// <summary>Unique identifier of the user.</summary>
    public Guid Id { get; init; }

    /// <summary>Email address, used as the login identifier. Unique across users.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Optional display name shown in the UI. Null when the user has not set one.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Hash of the user's password (never the plain text). Empty for externally-authenticated users.</summary>
    public string PasswordHash { get; init; } = string.Empty;

    /// <summary>Role that determines the user's permissions across the system.</summary>
    public UserRole Role { get; init; }

    /// <summary>Whether the account is active and permitted to sign in.</summary>
    public bool IsActive { get; init; }

    /// <summary>UTC timestamp when the account was created.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>UTC timestamp of the user's most recent successful login. Null if never logged in.</summary>
    public DateTime? LastLoginAt { get; init; }

    /// <summary>Number of consecutive failed login attempts.</summary>
    public int FailedLoginAttempts { get; init; }

    /// <summary>UTC time when the account lockout expires. Null means not locked.</summary>
    public DateTime? LockoutEnd { get; init; }

    /// <summary>External subject identifier from an OIDC provider (null for built-in users).</summary>
    public string? ExternalId { get; init; }

    /// <summary>Which authentication provider owns this user.</summary>
    public AuthenticationProvider AuthenticationProvider { get; init; } = AuthenticationProvider.BuiltIn;

    /// <summary>
    /// Indicates whether the user has changed their password from the initial seeded value.
    /// Used to determine if development credentials should still be shown on the login page.
    /// </summary>
    public bool HasChangedPassword { get; init; }

    /// <summary>Returns true if the account is currently locked out.</summary>
    public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd.Value > DateTime.UtcNow;
}
