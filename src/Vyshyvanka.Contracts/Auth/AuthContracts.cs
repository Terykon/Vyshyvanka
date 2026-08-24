namespace Vyshyvanka.Contracts.Auth;

/// <summary>
/// Request payload for authenticating a user with email and password.
/// </summary>
public record LoginRequest
{
    /// <summary>Email address identifying the user account.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Plain-text password for the account. Transmitted only over HTTPS and never persisted by the client.</summary>
    public string Password { get; init; } = string.Empty;
}

/// <summary>
/// Response returned on successful login, carrying the issued tokens and user profile.
/// </summary>
public record LoginResponse
{
    /// <summary>Short-lived bearer token used to authorize subsequent API requests.</summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>Long-lived token used to obtain a new <see cref="AccessToken"/> without re-entering credentials.</summary>
    public string RefreshToken { get; init; } = string.Empty;

    /// <summary>UTC timestamp at which the <see cref="AccessToken"/> expires.</summary>
    public DateTime ExpiresAt { get; init; }

    /// <summary>Profile of the authenticated user.</summary>
    public UserInfo User { get; init; } = null!;
}

/// <summary>
/// Minimal user profile returned from authentication endpoints.
/// </summary>
public record UserInfo
{
    /// <summary>Unique identifier of the user.</summary>
    public Guid Id { get; init; }

    /// <summary>Email address of the user.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Optional display name shown in the UI. <c>null</c> when the user has not set one.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Role name that determines the user's permissions (e.g. <c>Admin</c>, <c>Editor</c>, <c>Viewer</c>).</summary>
    public string Role { get; init; } = string.Empty;
}

/// <summary>
/// Request payload to exchange a refresh token for a new access token.
/// </summary>
public record RefreshRequest
{
    /// <summary>The refresh token previously issued at login.</summary>
    public string RefreshToken { get; init; } = string.Empty;
}

/// <summary>
/// Request payload to change the current user's password.
/// </summary>
public record ChangePasswordRequest
{
    /// <summary>The user's current password for verification.</summary>
    public string CurrentPassword { get; init; } = string.Empty;

    /// <summary>The new password to set.</summary>
    public string NewPassword { get; init; } = string.Empty;
}

/// <summary>
/// Public authentication configuration the Designer uses to adapt its login flow.
/// Returned anonymously so the client can determine the active provider before authenticating.
/// </summary>
public record AuthConfigResponse
{
    /// <summary>Active authentication provider (e.g. <c>BuiltIn</c>, <c>Keycloak</c>, <c>Authentik</c>, <c>Ldap</c>).</summary>
    public string Provider { get; init; } = string.Empty;

    /// <summary>OIDC authority URL for external providers. <c>null</c> for non-OIDC providers.</summary>
    public string? Authority { get; init; }

    /// <summary>OIDC client identifier for external providers. <c>null</c> for non-OIDC providers.</summary>
    public string? ClientId { get; init; }

    /// <summary>Whether self-service user registration is permitted for the active provider.</summary>
    public bool AllowRegistration { get; init; }

    /// <summary>
    /// Whether the development credentials panel should be shown on the login page.
    /// True when using BuiltIn auth and at least one seeded user has not changed their password.
    /// </summary>
    public bool ShowDevCredentials { get; init; }
}

/// <summary>
/// Administrative view of a user account, including status and provenance fields.
/// </summary>
public record AdminUserResponse
{
    /// <summary>Unique identifier of the user.</summary>
    public Guid Id { get; init; }

    /// <summary>Email address of the user.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Optional display name. <c>null</c> when unset.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Role name that determines the user's permissions.</summary>
    public string Role { get; init; } = string.Empty;

    /// <summary>Whether the account is active and permitted to sign in.</summary>
    public bool IsActive { get; init; }

    /// <summary>Whether the account is currently locked out (e.g. after failed login attempts).</summary>
    public bool IsLockedOut { get; init; }

    /// <summary>Provider that authenticates this user (e.g. <c>BuiltIn</c>, <c>Keycloak</c>, <c>Ldap</c>).</summary>
    public string AuthenticationProvider { get; init; } = string.Empty;

    /// <summary>UTC timestamp when the account was created.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>UTC timestamp of the user's most recent login. <c>null</c> if they have never logged in.</summary>
    public DateTime? LastLoginAt { get; init; }
}

/// <summary>
/// Paginated collection of administrative user records.
/// </summary>
public record UserListResponse
{
    /// <summary>The users on the current page.</summary>
    public List<AdminUserResponse> Users { get; init; } = [];

    /// <summary>Total number of users matching the query across all pages.</summary>
    public int TotalCount { get; init; }
}

/// <summary>
/// Request payload for an administrator to create a user. Applies only to the BuiltIn provider.
/// </summary>
public record CreateUserRequest
{
    /// <summary>Email address for the new account. Must be unique.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Initial plain-text password for the new account.</summary>
    public string Password { get; init; } = string.Empty;

    /// <summary>Optional display name for the new user.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Role to assign to the new user. Defaults to <c>Editor</c>.</summary>
    public string Role { get; init; } = "Editor";
}

/// <summary>
/// Request payload to change a user's role.
/// </summary>
public record UpdateUserRoleRequest
{
    /// <summary>New role name to assign to the user.</summary>
    public string Role { get; init; } = string.Empty;
}

/// <summary>
/// Request payload to enable or disable a user account.
/// </summary>
public record UpdateUserStatusRequest
{
    /// <summary>Whether the account should be active (<c>true</c>) or disabled (<c>false</c>).</summary>
    public bool IsActive { get; init; }
}

/// <summary>
/// Request payload for a user to update their own profile.
/// </summary>
public record UpdateUserProfileRequest
{
    /// <summary>Updated email address for the account.</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>Updated display name. <c>null</c> clears the display name.</summary>
    public string? DisplayName { get; init; }
}

/// <summary>
/// Request payload to create a new API key for machine-to-machine access.
/// </summary>
public record CreateApiKeyRequest
{
    /// <summary>Human-readable label for the key, used to identify it in the UI.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Optional set of scopes limiting what the key may do. <c>null</c> grants the caller's default scopes.</summary>
    public List<string>? Scopes { get; init; }

    /// <summary>Optional UTC expiry time. <c>null</c> creates a key that never expires.</summary>
    public DateTime? ExpiresAt { get; init; }
}

/// <summary>
/// Response after creating an API key. This is the only time the plain-text key is returned.
/// </summary>
public record CreateApiKeyResponse
{
    /// <summary>Unique identifier of the API key.</summary>
    public Guid Id { get; init; }

    /// <summary>Human-readable label for the key.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// The plain-text API key value. Shown only once at creation and never returned again;
    /// the client must store it securely.
    /// </summary>
    public string Key { get; init; } = string.Empty;

    /// <summary>The scopes granted to the key.</summary>
    public List<string> Scopes { get; init; } = [];

    /// <summary>UTC timestamp when the key was created.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>UTC expiry time. <c>null</c> when the key never expires.</summary>
    public DateTime? ExpiresAt { get; init; }
}

/// <summary>
/// API key representation for list and get operations. Never includes the plain-text key.
/// </summary>
public record ApiKeyResponse
{
    /// <summary>Unique identifier of the API key.</summary>
    public Guid Id { get; init; }

    /// <summary>Human-readable label for the key.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>The scopes granted to the key.</summary>
    public List<string> Scopes { get; init; } = [];

    /// <summary>UTC timestamp when the key was created.</summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>UTC expiry time. <c>null</c> when the key never expires.</summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>UTC timestamp when the key was last used to authenticate. <c>null</c> if never used.</summary>
    public DateTime? LastUsedAt { get; init; }

    /// <summary>Whether the key is currently active and accepted for authentication.</summary>
    public bool IsActive { get; init; }
}
