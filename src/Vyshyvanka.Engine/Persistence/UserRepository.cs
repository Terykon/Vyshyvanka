using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Vyshyvanka.Core.Interfaces;
using Vyshyvanka.Core.Models;
using Vyshyvanka.Engine.Persistence.Entities;

namespace Vyshyvanka.Engine.Persistence;

/// <summary>
/// EF Core implementation of user repository.
/// </summary>
public class UserRepository(VyshyvankaDbContext context) : IUserRepository
{
    /// <summary>
    /// Hashes a refresh token with SHA-256 for storage/lookup. Refresh tokens are already
    /// 512-bit cryptographically random, so a plain (unsalted) hash is sufficient — the token
    /// is a high-entropy secret, not a guessable password, so no PBKDF2/salt is required.
    /// </summary>
    private static string HashRefreshToken(string refreshToken) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken)));

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var entity = await context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == id, cancellationToken);

        return entity is null ? null : ToModel(entity);
    }

    public async Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var entity = await context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == email, cancellationToken);

        return entity is null ? null : ToModel(entity);
    }

    public async Task<User?> GetByExternalIdAsync(string externalId, CancellationToken cancellationToken = default)
    {
        var entity = await context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.ExternalId == externalId, cancellationToken);

        return entity is null ? null : ToModel(entity);
    }

    public async Task<User> CreateAsync(User user, CancellationToken cancellationToken = default)
    {
        var entity = ToEntity(user);
        context.Users.Add(entity);
        await context.SaveChangesAsync(cancellationToken);
        return ToModel(entity);
    }

    public async Task<User> UpdateAsync(User user, CancellationToken cancellationToken = default)
    {
        var entity = await context.Users.FindAsync([user.Id], cancellationToken)
                     ?? throw new InvalidOperationException($"User {user.Id} not found");

        entity.Email = user.Email;
        entity.DisplayName = user.DisplayName;
        entity.PasswordHash = user.PasswordHash;
        entity.Role = user.Role;
        entity.IsActive = user.IsActive;
        entity.LastLoginAt = user.LastLoginAt;
        entity.FailedLoginAttempts = user.FailedLoginAttempts;
        entity.LockoutEnd = user.LockoutEnd;
        entity.HasChangedPassword = user.HasChangedPassword;

        await context.SaveChangesAsync(cancellationToken);
        return ToModel(entity);
    }

    public async Task<IEnumerable<User>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var entities = await context.Users
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        return entities.Select(ToModel);
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var entity = await context.Users.FindAsync([id], cancellationToken);
        if (entity is not null)
        {
            context.Users.Remove(entity);
            await context.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<bool> HasUnchangedSeededPasswordsAsync(CancellationToken cancellationToken = default)
    {
        // Check if any seeded development user still has their original password unchanged.
        // Seeded users are identified by their well-known email addresses.
        var seededEmails = new[]
        {
            "admin@vyshyvanka.local",
            "editor@vyshyvanka.local",
            "viewer@vyshyvanka.local"
        };

        return await context.Users
            .AsNoTracking()
            .AnyAsync(
                u => seededEmails.Contains(u.Email) && !u.HasChangedPassword,
                cancellationToken);
    }

    internal async Task UpdateRefreshTokenAsync(Guid userId, string? refreshToken, DateTime? expiresAt,
        CancellationToken cancellationToken = default)
    {
        var entity = await context.Users.FindAsync([userId], cancellationToken)
                     ?? throw new InvalidOperationException($"User {userId} not found");

        // Store only the hash of the refresh token — never the plaintext.
        entity.RefreshToken = refreshToken is null ? null : HashRefreshToken(refreshToken);
        entity.RefreshTokenExpiresAt = expiresAt;
        await context.SaveChangesAsync(cancellationToken);
    }

    internal async Task<(string? RefreshToken, DateTime? ExpiresAt)> GetRefreshTokenAsync(Guid userId,
        CancellationToken cancellationToken = default)
    {
        var entity = await context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId, cancellationToken);

        return entity is null ? (null, null) : (entity.RefreshToken, entity.RefreshTokenExpiresAt);
    }

    internal async Task<User?> GetByRefreshTokenAsync(string refreshToken,
        CancellationToken cancellationToken = default)
    {
        // The stored value is a hash, so look up by the hash of the presented token.
        var hash = HashRefreshToken(refreshToken);
        var entity = await context.Users
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.RefreshToken == hash, cancellationToken);

        return entity is null ? null : ToModel(entity);
    }

    /// <summary>
    /// Verifies a presented refresh token against the stored hash in fixed time.
    /// <paramref name="storedHash"/> is the value returned by <see cref="GetRefreshTokenAsync"/>.
    /// </summary>
    internal static bool VerifyRefreshToken(string presentedToken, string? storedHash)
    {
        if (string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        var presentedHash = HashRefreshToken(presentedToken);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presentedHash),
            Encoding.UTF8.GetBytes(storedHash));
    }

    private static User ToModel(UserEntity entity) => new()
    {
        Id = entity.Id,
        Email = entity.Email,
        DisplayName = entity.DisplayName,
        PasswordHash = entity.PasswordHash,
        Role = entity.Role,
        IsActive = entity.IsActive,
        CreatedAt = entity.CreatedAt,
        LastLoginAt = entity.LastLoginAt,
        FailedLoginAttempts = entity.FailedLoginAttempts,
        LockoutEnd = entity.LockoutEnd,
        ExternalId = entity.ExternalId,
        AuthenticationProvider = entity.AuthenticationProvider,
        HasChangedPassword = entity.HasChangedPassword
    };

    private static UserEntity ToEntity(User model) => new()
    {
        Id = model.Id,
        Email = model.Email,
        DisplayName = model.DisplayName,
        PasswordHash = model.PasswordHash,
        Role = model.Role,
        IsActive = model.IsActive,
        CreatedAt = model.CreatedAt,
        LastLoginAt = model.LastLoginAt,
        FailedLoginAttempts = model.FailedLoginAttempts,
        LockoutEnd = model.LockoutEnd,
        ExternalId = model.ExternalId,
        AuthenticationProvider = model.AuthenticationProvider,
        HasChangedPassword = model.HasChangedPassword
    };
}
