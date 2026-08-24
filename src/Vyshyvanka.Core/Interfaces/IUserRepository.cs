using Vyshyvanka.Core.Models;

namespace Vyshyvanka.Core.Interfaces;

/// <summary>
/// Repository for user data access.
/// </summary>
public interface IUserRepository
{
    /// <summary>Gets a user by unique identifier, or null when none exists.</summary>
    Task<User?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>Gets a user by email address, or null when none exists.</summary>
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>Gets a user by external OIDC subject identifier, or null when none exists.</summary>
    Task<User?> GetByExternalIdAsync(string externalId, CancellationToken cancellationToken = default);

    /// <summary>Persists a new user and returns the stored record.</summary>
    Task<User> CreateAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>Updates an existing user and returns the stored record.</summary>
    Task<User> UpdateAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>Gets all users.</summary>
    Task<IEnumerable<User>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Deletes the user with the given identifier.</summary>
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if any seeded development user still has their original password unchanged.
    /// Used to determine if development credentials should be shown on the login page.
    /// </summary>
    Task<bool> HasUnchangedSeededPasswordsAsync(CancellationToken cancellationToken = default);
}
