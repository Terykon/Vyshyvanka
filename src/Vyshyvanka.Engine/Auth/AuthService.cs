using System.Security.Cryptography;
using Vyshyvanka.Core.Enums;
using Vyshyvanka.Core.Interfaces;
using Vyshyvanka.Core.Models;
using Vyshyvanka.Engine.Persistence;

namespace Vyshyvanka.Engine.Auth;

/// <summary>
/// Authentication service for user login and registration.
/// </summary>
public class AuthService : IAuthService
{
    /// <summary>Maximum consecutive failed login attempts before lockout.</summary>
    private const int MaxFailedAttempts = 5;

    /// <summary>Duration of account lockout after exceeding max failed attempts.</summary>
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly IUserRepository _userRepository;
    private readonly UserRepository _userRepositoryInternal;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly JwtSettings _jwtSettings;
    private readonly AuthenticationSettings _authSettings;
    private readonly IAuditLogService? _auditLogService;

    public AuthService(
        IUserRepository userRepository,
        IJwtTokenService jwtTokenService,
        JwtSettings jwtSettings,
        AuthenticationSettings authSettings,
        IAuditLogService? auditLogService = null)
    {
        _userRepository = userRepository;
        _userRepositoryInternal = (UserRepository)userRepository;
        _jwtTokenService = jwtTokenService;
        _jwtSettings = jwtSettings;
        _authSettings = authSettings;
        _auditLogService = auditLogService;
    }

    public async Task<AuthResult> LoginAsync(string email, string password,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        var user = await _userRepository.GetByEmailAsync(email, cancellationToken);

        if (user is null)
        {
            await LogAuthenticationAsync(email, false, "Invalid email or password", cancellationToken);
            return new AuthResult { Success = false, ErrorMessage = "Invalid email or password" };
        }

        if (!user.IsActive)
        {
            await LogAuthenticationAsync(email, false, "Account is disabled", cancellationToken);
            return new AuthResult { Success = false, ErrorMessage = "Account is disabled" };
        }

        if (user.IsLockedOut)
        {
            var remainingSeconds = (int)(user.LockoutEnd!.Value - DateTime.UtcNow).TotalSeconds;
            await LogAuthenticationAsync(email, false, "Account is locked", cancellationToken);
            return new AuthResult
            {
                Success = false,
                ErrorMessage =
                    $"Account is locked due to too many failed login attempts. Try again in {remainingSeconds} seconds."
            };
        }

        if (!VerifyPassword(password, user.PasswordHash))
        {
            await RecordFailedLoginAttemptAsync(user, cancellationToken);
            await LogAuthenticationAsync(email, false, "Invalid email or password", cancellationToken);
            return new AuthResult { Success = false, ErrorMessage = "Invalid email or password" };
        }

        // Successful login — reset lockout state
        if (user.FailedLoginAttempts > 0)
        {
            user = user with { FailedLoginAttempts = 0, LockoutEnd = null };
            await _userRepository.UpdateAsync(user, cancellationToken);
        }

        var accessToken = _jwtTokenService.GenerateAccessToken(user);
        var refreshToken = _jwtTokenService.GenerateRefreshToken();
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);

        await _userRepositoryInternal.UpdateRefreshTokenAsync(user.Id, refreshToken, refreshTokenExpiry,
            cancellationToken);

        var updatedUser = user with { LastLoginAt = DateTime.UtcNow };
        await _userRepository.UpdateAsync(updatedUser, cancellationToken);

        await LogAuthenticationAsync(email, true, null, cancellationToken);

        return new AuthResult
        {
            Success = true,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            User = updatedUser
        };
    }

    public async Task<AuthResult> RegisterAsync(string email, string password, string? displayName = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        // Validate email format
        if (!System.Net.Mail.MailAddress.TryCreate(email, out _))
        {
            return new AuthResult { Success = false, ErrorMessage = "Invalid email format" };
        }

        // Validate password complexity
        var passwordValidation = PasswordValidator.Validate(password, _authSettings.MinPasswordLength);
        if (!passwordValidation.IsValid)
        {
            return new AuthResult { Success = false, ErrorMessage = passwordValidation.ErrorMessage };
        }

        var existingUser = await _userRepository.GetByEmailAsync(email, cancellationToken);
        if (existingUser is not null)
        {
            return new AuthResult { Success = false, ErrorMessage = "Email already registered" };
        }

        var passwordHash = HashPassword(password);
        var isActive = !_authSettings.RequireAdminApproval;

        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            DisplayName = displayName,
            PasswordHash = passwordHash,
            Role = UserRole.Viewer,
            IsActive = isActive,
            CreatedAt = DateTime.UtcNow
        };

        var createdUser = await _userRepository.CreateAsync(user, cancellationToken);

        // If admin approval is required, don't issue tokens — account is inactive
        if (!isActive)
        {
            return new AuthResult
            {
                Success = true,
                ErrorMessage = "Account created but requires admin approval before you can log in",
                User = createdUser
            };
        }

        var accessToken = _jwtTokenService.GenerateAccessToken(createdUser);
        var refreshToken = _jwtTokenService.GenerateRefreshToken();
        var refreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);

        await _userRepositoryInternal.UpdateRefreshTokenAsync(createdUser.Id, refreshToken, refreshTokenExpiry,
            cancellationToken);

        return new AuthResult
        {
            Success = true,
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            User = createdUser
        };
    }

    public async Task<AuthResult> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        var user = await _userRepositoryInternal.GetByRefreshTokenAsync(refreshToken, cancellationToken);
        if (user is null)
        {
            return new AuthResult { Success = false, ErrorMessage = "Invalid refresh token" };
        }

        var (storedToken, expiresAt) = await _userRepositoryInternal.GetRefreshTokenAsync(user.Id, cancellationToken);

        if (!UserRepository.VerifyRefreshToken(refreshToken, storedToken) || expiresAt < DateTime.UtcNow)
        {
            return new AuthResult { Success = false, ErrorMessage = "Refresh token expired" };
        }

        if (!user.IsActive)
        {
            return new AuthResult { Success = false, ErrorMessage = "Account is disabled" };
        }

        var newAccessToken = _jwtTokenService.GenerateAccessToken(user);
        var newRefreshToken = _jwtTokenService.GenerateRefreshToken();
        var newRefreshTokenExpiry = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays);

        await _userRepositoryInternal.UpdateRefreshTokenAsync(user.Id, newRefreshToken, newRefreshTokenExpiry,
            cancellationToken);

        return new AuthResult
        {
            Success = true,
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            User = user
        };
    }

    public Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var result = _jwtTokenService.ValidateToken(token);
        return Task.FromResult(result.IsValid);
    }

    public string HashPassword(string password)
    {
        var salt = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100000, HashAlgorithmName.SHA256, 32);

        var hashBytes = new byte[48];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 32);

        return Convert.ToBase64String(hashBytes);
    }

    public bool VerifyPassword(string password, string passwordHash)
    {
        var hashBytes = Convert.FromBase64String(passwordHash);

        var salt = new byte[16];
        Array.Copy(hashBytes, 0, salt, 0, 16);

        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100000, HashAlgorithmName.SHA256, 32);

        return CryptographicOperations.FixedTimeEquals(hashBytes.AsSpan(16), hash);
    }

    private async Task LogAuthenticationAsync(string email, bool success, string? errorMessage,
        CancellationToken cancellationToken)
    {
        if (_auditLogService is not null)
        {
            await _auditLogService.LogAuthenticationAttemptAsync(email, success, null, null, errorMessage,
                cancellationToken);
        }
    }

    public async Task UnlockAccountAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var user = await _userRepository.GetByIdAsync(userId, cancellationToken)
                   ?? throw new InvalidOperationException($"User {userId} not found");

        var unlockedUser = user with { FailedLoginAttempts = 0, LockoutEnd = null };
        await _userRepository.UpdateAsync(unlockedUser, cancellationToken);
    }

    public async Task<(bool Success, string? ErrorMessage)> ChangePasswordAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return (false, "User not found");
        }

        // Verify current password
        if (!VerifyPassword(currentPassword, user.PasswordHash))
        {
            return (false, "Current password is incorrect");
        }

        // Validate new password complexity
        var passwordValidation = PasswordValidator.Validate(newPassword, _authSettings.MinPasswordLength);
        if (!passwordValidation.IsValid)
        {
            return (false, passwordValidation.ErrorMessage);
        }

        // Update password and mark as changed
        var newPasswordHash = HashPassword(newPassword);
        var updatedUser = user with
        {
            PasswordHash = newPasswordHash,
            HasChangedPassword = true
        };

        await _userRepository.UpdateAsync(updatedUser, cancellationToken);

        return (true, null);
    }

    private async Task RecordFailedLoginAttemptAsync(User user, CancellationToken cancellationToken)
    {
        var attempts = user.FailedLoginAttempts + 1;
        DateTime? lockoutEnd = attempts >= MaxFailedAttempts
            ? DateTime.UtcNow.Add(LockoutDuration)
            : null;

        var updatedUser = user with { FailedLoginAttempts = attempts, LockoutEnd = lockoutEnd };
        await _userRepository.UpdateAsync(updatedUser, cancellationToken);
    }
}
