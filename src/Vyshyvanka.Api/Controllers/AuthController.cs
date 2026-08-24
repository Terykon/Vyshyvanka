using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vyshyvanka.Api.Authorization;
using Vyshyvanka.Api.Extensions;
using Vyshyvanka.Contracts.Auth;
using Vyshyvanka.Core.Enums;
using Vyshyvanka.Core.Interfaces;
using Vyshyvanka.Core.Models;

namespace Vyshyvanka.Api.Controllers;

/// <summary>
/// Authentication endpoints.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController(
    AuthenticationSettings authSettings,
    IServiceProvider serviceProvider) : ControllerBase
{
    /// <summary>
    /// Returns the active authentication provider and OIDC settings so the
    /// client (Blazor WASM) can configure its own auth flow.
    /// </summary>
    [HttpGet("config")]
    [AllowAnonymous]
    public async Task<IActionResult> GetConfig(CancellationToken cancellationToken)
    {
        var isOidc = authSettings.Provider is AuthenticationProvider.Keycloak or AuthenticationProvider.Authentik;
        var isBuiltIn = authSettings.Provider is AuthenticationProvider.BuiltIn;

        // Only check for unchanged seeded passwords when using built-in auth
        var showDevCredentials = false;
        if (isBuiltIn)
        {
            var userRepository = serviceProvider.GetRequiredService<IUserRepository>();
            showDevCredentials = await userRepository.HasUnchangedSeededPasswordsAsync(cancellationToken);
        }

        return Ok(new AuthConfigResponse
        {
            Provider = authSettings.Provider.ToString(),
            Authority = isOidc ? authSettings.Authority : null,
            ClientId = isOidc ? authSettings.ClientId : null,
            AllowRegistration = isBuiltIn && authSettings.AllowRegistration,
            ShowDevCredentials = showDevCredentials
        });
    }

    /// <summary>
    /// Login with email/username and password (built-in and LDAP providers).
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingExtensions.AuthPolicy)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        if (authSettings.Provider is AuthenticationProvider.Keycloak or AuthenticationProvider.Authentik)
        {
            return BadRequest(new
            {
                code = "UNSUPPORTED",
                message = $"Login endpoint is not available when using {authSettings.Provider} authentication"
            });
        }

        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { error = "Email and password are required" });
        }

        var authService = serviceProvider.GetRequiredService<IAuthService>();
        var result = await authService.LoginAsync(request.Email, request.Password, cancellationToken);

        if (!result.Success)
        {
            return Unauthorized(new { error = result.ErrorMessage });
        }

        return Ok(ToLoginResponse(result));
    }

    /// <summary>
    /// Register a new user (built-in provider only).
    /// </summary>
    [HttpPost("register")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingExtensions.AuthPolicy)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        if (authSettings.Provider is not AuthenticationProvider.BuiltIn)
        {
            return BadRequest(new
            {
                code = "UNSUPPORTED",
                message = $"Registration is not available when using {authSettings.Provider} authentication"
            });
        }

        if (!authSettings.AllowRegistration)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                code = "REGISTRATION_DISABLED",
                message = "Open registration is disabled. Contact an administrator to create an account."
            });
        }

        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { error = "Email and password are required" });
        }

        var authService = serviceProvider.GetRequiredService<IAuthService>();
        var result =
            await authService.RegisterAsync(request.Email, request.Password, request.DisplayName, cancellationToken);

        if (!result.Success)
        {
            return BadRequest(new { error = result.ErrorMessage });
        }

        // If admin approval is required, tokens won't be present
        if (result.AccessToken is null)
        {
            return Ok(new { message = result.ErrorMessage, userId = result.User?.Id });
        }

        return Ok(ToLoginResponse(result));
    }

    /// <summary>
    /// Refresh access token (built-in and LDAP providers).
    /// </summary>
    [HttpPost("refresh")]
    [AllowAnonymous]
    [EnableRateLimiting(RateLimitingExtensions.AuthPolicy)]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request, CancellationToken cancellationToken)
    {
        if (authSettings.Provider is AuthenticationProvider.Keycloak or AuthenticationProvider.Authentik)
        {
            return BadRequest(new
            {
                code = "UNSUPPORTED",
                message = $"Token refresh endpoint is not available when using {authSettings.Provider} authentication"
            });
        }

        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest(new { error = "Refresh token is required" });
        }

        var authService = serviceProvider.GetRequiredService<IAuthService>();
        var result = await authService.RefreshTokenAsync(request.RefreshToken, cancellationToken);

        if (!result.Success)
        {
            return Unauthorized(new { error = result.ErrorMessage });
        }

        return Ok(ToLoginResponse(result));
    }

    /// <summary>
    /// Change the current user's password (built-in provider only).
    /// </summary>
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword(
        [FromBody] ChangePasswordRequest request,
        [FromServices] ICurrentUserService currentUserService,
        CancellationToken cancellationToken)
    {
        if (authSettings.Provider is not AuthenticationProvider.BuiltIn)
        {
            return BadRequest(new
            {
                code = "UNSUPPORTED",
                message = $"Password change is not available when using {authSettings.Provider} authentication"
            });
        }

        if (string.IsNullOrWhiteSpace(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new { error = "Current password and new password are required" });
        }

        if (currentUserService.UserId is not { } userId)
        {
            return Unauthorized(new { error = "User not authenticated" });
        }

        var authService = serviceProvider.GetRequiredService<IAuthService>();
        var (success, errorMessage) = await authService.ChangePasswordAsync(
            userId,
            request.CurrentPassword,
            request.NewPassword,
            cancellationToken);

        if (!success)
        {
            return BadRequest(new { error = errorMessage });
        }

        return Ok(new { message = "Password changed successfully" });
    }

    private static LoginResponse ToLoginResponse(AuthResult result) => new()
    {
        AccessToken = result.AccessToken!,
        RefreshToken = result.RefreshToken!,
        ExpiresAt = result.ExpiresAt!.Value,
        User = new UserResponse
        {
            Id = result.User!.Id,
            Email = result.User.Email,
            DisplayName = result.User.DisplayName,
            Role = result.User.Role.ToString()
        }
    };

    /// <summary>
    /// Unlock a user account that has been locked due to too many failed login attempts.
    /// Requires Admin role.
    /// </summary>
    [HttpPost("unlock/{userId:guid}")]
    [Authorize(Policy = Policies.CanManageUsers)]
    public async Task<IActionResult> UnlockAccount(Guid userId, CancellationToken cancellationToken)
    {
        var authService = serviceProvider.GetRequiredService<IAuthService>();

        try
        {
            await authService.UnlockAccountAsync(userId, cancellationToken);
            return Ok(new { message = "Account unlocked successfully" });
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("not found"))
        {
            return NotFound(new { code = "USER_NOT_FOUND", message = ex.Message });
        }
    }
}

public record LoginRequest
{
    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;
}

public record RegisterRequest
{
    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string? DisplayName { get; init; }
}

public record RefreshRequest
{
    public string RefreshToken { get; init; } = string.Empty;
}

public record LoginResponse
{
    public string AccessToken { get; init; } = string.Empty;

    public string RefreshToken { get; init; } = string.Empty;

    public DateTime ExpiresAt { get; init; }

    public UserResponse User { get; init; } = null!;
}

public record UserResponse
{
    public Guid Id { get; init; }

    public string Email { get; init; } = string.Empty;

    public string? DisplayName { get; init; }

    public string Role { get; init; } = string.Empty;
}
