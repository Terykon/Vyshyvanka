using Vyshyvanka.Core.Interfaces;
using Vyshyvanka.Core.Models;

namespace Vyshyvanka.Engine.Auth;

/// <summary>
/// <see cref="IAuthService"/> implementation that delegates credential verification
/// to an LDAP directory while issuing local JWT tokens for session management.
/// Registration is not supported — users are provisioned automatically on first LDAP login.
/// </summary>
public class LdapAuthService(
    ILdapAuthenticationService ldapService,
    IJwtTokenService jwtTokenService,
    JwtSettings jwtSettings,
    IUserRepository userRepository,
    IAuditLogService? auditLogService = null) : IAuthService
{
    /// <summary>Maximum consecutive failed login attempts before lockout.</summary>
    private const int MaxFailedAttempts = 5;

    /// <summary>Duration of account lockout after exceeding max failed attempts.</summary>
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public async Task<AuthResult> LoginAsync(string email, string password,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        // Check lockout state before attempting LDAP bind
        var existingUser = await userRepository.GetByEmailAsync(email, cancellationToken);
        if (existingUser is not null)
        {
            if (!existingUser.IsActive)
            {
                await LogAuthAsync(email, false, "Account is disabled", cancellationToken);
                return new AuthResult { Success = false, ErrorMessage = "Account is disabled" };
            }

            if (existingUser.IsLockedOut)
            {
                var remainingSeconds = (int)(existingUser.LockoutEnd!.Value - DateTime.UtcNow).TotalSeconds;
                await LogAuthAsync(email, false, "Account is locked", cancellationToken);
                return new AuthResult
                {
                    Success = false,
                    ErrorMessage =
                        $"Account is locked due to too many failed login attempts. Try again in {remainingSeconds} seconds."
                };
            }
        }

        var ldapResult = await ldapService.AuthenticateAsync(email, password, cancellationToken);

        if (!ldapResult.Success || ldapResult.User is null)
        {
            // Record failed attempt if user exists locally
            if (existingUser is not null)
            {
                await RecordFailedLoginAttemptAsync(existingUser, cancellationToken);
            }

            await LogAuthAsync(email, false, ldapResult.ErrorMessage, cancellationToken);
            return new AuthResult { Success = false, ErrorMessage = ldapResult.ErrorMessage ?? "Invalid credentials" };
        }

        var user = ldapResult.User;

        // Reset lockout state on successful login
        if (user.FailedLoginAttempts > 0)
        {
            user = user with { FailedLoginAttempts = 0, LockoutEnd = null };
            await userRepository.UpdateAsync(user, cancellationToken);
        }

        var accessToken = jwtTokenService.GenerateAccessToken(user);
        var refreshToken = jwtTokenService.GenerateRefreshToken();
        var refreshExpiry = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenExpirationDays);

        // Store refresh token on the local user record
        if (userRepository is Engine.Persistence.UserRepository repo)
        {
            await repo.UpdateRefreshTokenAsync(user.Id, refreshToken, refreshExpiry, cancellationToken);
        }

        await LogAuthAsync(email, true, null, cancellationToken);

        return new AuthResult
        {
            Success = true,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpirationMinutes),
            User = user
        };
    }

    public Task<AuthResult> RegisterAsync(string email, string password, string? displayName = null,
        CancellationToken cancellationToken = default)
    {
        // Self-registration is not supported with LDAP — users are provisioned on first login
        return Task.FromResult(new AuthResult
        {
            Success = false,
            ErrorMessage = "Registration is not available when using LDAP authentication"
        });
    }

    public async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        if (userRepository is not Engine.Persistence.UserRepository repo)
        {
            return new AuthResult { Success = false, ErrorMessage = "Token refresh not supported" };
        }

        var user = await repo.GetByRefreshTokenAsync(refreshToken, cancellationToken);
        if (user is null)
        {
            return new AuthResult { Success = false, ErrorMessage = "Invalid refresh token" };
        }

        var (storedToken, expiresAt) = await repo.GetRefreshTokenAsync(user.Id, cancellationToken);
        if (!Engine.Persistence.UserRepository.VerifyRefreshToken(refreshToken, storedToken) ||
            expiresAt < DateTime.UtcNow)
        {
            return new AuthResult { Success = false, ErrorMessage = "Refresh token expired" };
        }

        if (!user.IsActive)
        {
            return new AuthResult { Success = false, ErrorMessage = "Account is disabled" };
        }

        var newAccessToken = jwtTokenService.GenerateAccessToken(user);
        var newRefreshToken = jwtTokenService.GenerateRefreshToken();
        var newExpiry = DateTime.UtcNow.AddDays(jwtSettings.RefreshTokenExpirationDays);

        await repo.UpdateRefreshTokenAsync(user.Id, newRefreshToken, newExpiry, cancellationToken);

        return new AuthResult
        {
            Success = true,
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpirationMinutes),
            User = user
        };
    }

    public Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var result = jwtTokenService.ValidateToken(token);
        return Task.FromResult(result.IsValid);
    }

    public string HashPassword(string password) =>
        throw new NotSupportedException("Password hashing is not used with LDAP authentication");

    public bool VerifyPassword(string password, string passwordHash) =>
        throw new NotSupportedException("Password verification is not used with LDAP authentication");

    public async Task UnlockAccountAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await userRepository.GetByIdAsync(userId, cancellationToken)
                   ?? throw new InvalidOperationException($"User {userId} not found");

        var unlockedUser = user with { FailedLoginAttempts = 0, LockoutEnd = null };
        await userRepository.UpdateAsync(unlockedUser, cancellationToken);
    }

    public Task<(bool Success, string? ErrorMessage)> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        // Password changes are not supported with LDAP — users must change password via LDAP directory
        return Task.FromResult<(bool, string?)>((false, "Password changes are not available when using LDAP authentication. Please change your password via your organization's LDAP directory."));
    }

    private async Task RecordFailedLoginAttemptAsync(User user, CancellationToken cancellationToken)
    {
        var attempts = user.FailedLoginAttempts + 1;
        DateTime? lockoutEnd = attempts >= MaxFailedAttempts
            ? DateTime.UtcNow.Add(LockoutDuration)
            : null;

        var updatedUser = user with { FailedLoginAttempts = attempts, LockoutEnd = lockoutEnd };
        await userRepository.UpdateAsync(updatedUser, cancellationToken);
    }

    private async Task LogAuthAsync(string email, bool success, string? error, CancellationToken ct)
    {
        if (auditLogService is not null)
        {
            await auditLogService.LogAuthenticationAttemptAsync(email, success, null, null, error, ct);
        }
    }
}
