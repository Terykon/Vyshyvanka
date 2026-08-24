using Microsoft.EntityFrameworkCore;
using Vyshyvanka.Core.Enums;
using Vyshyvanka.Core.Interfaces;
using Vyshyvanka.Core.Models;
using Vyshyvanka.Engine.Auth;
using Vyshyvanka.Engine.Persistence;

namespace Vyshyvanka.Tests.Unit;

public class AuthServiceTests : IDisposable
{
    private readonly VyshyvankaDbContext _dbContext;
    private readonly UserRepository _userRepository;
    private readonly IJwtTokenService _jwtTokenService = Substitute.For<IJwtTokenService>();
    private readonly JwtSettings _jwtSettings = new() { RefreshTokenExpirationDays = 7, AccessTokenExpirationMinutes = 15 };
    private readonly AuthenticationSettings _authSettings = new() { MinPasswordLength = 8 };
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        var options = new DbContextOptionsBuilder<VyshyvankaDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _dbContext = new VyshyvankaDbContext(options);
        _userRepository = new UserRepository(_dbContext);
        _sut = new AuthService(_userRepository, _jwtTokenService, _jwtSettings, _authSettings);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
    }

    [Fact]
    public async Task WhenChangingPasswordWithCorrectCurrentPasswordThenSucceeds()
    {
        var currentPassword = "OldPassword123!";
        var newPassword = "NewPassword456!";
        var user = await CreateTestUser(currentPassword);

        var (success, errorMessage) = await _sut.ChangePasswordAsync(user.Id, currentPassword, newPassword);

        success.Should().BeTrue();
        errorMessage.Should().BeNull();

        var updatedUser = await _userRepository.GetByIdAsync(user.Id);
        updatedUser!.HasChangedPassword.Should().BeTrue();
        _sut.VerifyPassword(newPassword, updatedUser.PasswordHash).Should().BeTrue();
    }

    [Fact]
    public async Task WhenChangingPasswordWithIncorrectCurrentPasswordThenFails()
    {
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword123!";
        var newPassword = "NewPassword456!";
        var user = await CreateTestUser(correctPassword);

        var (success, errorMessage) = await _sut.ChangePasswordAsync(user.Id, wrongPassword, newPassword);

        success.Should().BeFalse();
        errorMessage.Should().Be("Current password is incorrect");

        var unchangedUser = await _userRepository.GetByIdAsync(user.Id);
        unchangedUser!.HasChangedPassword.Should().BeFalse();
    }

    [Fact]
    public async Task WhenChangingPasswordForNonexistentUserThenFails()
    {
        var userId = Guid.NewGuid();

        var (success, errorMessage) = await _sut.ChangePasswordAsync(userId, "any", "NewPassword123!");

        success.Should().BeFalse();
        errorMessage.Should().Be("User not found");
    }

    [Fact]
    public async Task WhenChangingPasswordWithTooShortNewPasswordThenFails()
    {
        var currentPassword = "OldPassword123!";
        var shortPassword = "short";
        var user = await CreateTestUser(currentPassword);

        var (success, errorMessage) = await _sut.ChangePasswordAsync(user.Id, currentPassword, shortPassword);

        success.Should().BeFalse();
        errorMessage.Should().Contain("at least");

        var unchangedUser = await _userRepository.GetByIdAsync(user.Id);
        unchangedUser!.HasChangedPassword.Should().BeFalse();
    }

    [Fact]
    public async Task WhenChangingPasswordThenNewHashIsDifferentFromOld()
    {
        var currentPassword = "OldPassword123!";
        var newPassword = "NewPassword456!";
        var user = await CreateTestUser(currentPassword);
        var oldHash = user.PasswordHash;

        await _sut.ChangePasswordAsync(user.Id, currentPassword, newPassword);

        var updatedUser = await _userRepository.GetByIdAsync(user.Id);
        updatedUser!.PasswordHash.Should().NotBe(oldHash);
        _sut.VerifyPassword(newPassword, updatedUser.PasswordHash).Should().BeTrue();
    }

    [Fact]
    public async Task WhenChangingPasswordThenSetsHasChangedPasswordToTrue()
    {
        var currentPassword = "OldPassword123!";
        var newPassword = "NewPassword456!";
        var user = await CreateTestUser(currentPassword, hasChangedPassword: false);

        await _sut.ChangePasswordAsync(user.Id, currentPassword, newPassword);

        var updatedUser = await _userRepository.GetByIdAsync(user.Id);
        updatedUser!.HasChangedPassword.Should().BeTrue();
    }

    [Fact]
    public async Task WhenChangingPasswordForAlreadyChangedUserThenStillSucceeds()
    {
        var currentPassword = "CurrentPassword123!";
        var newPassword = "NewPassword456!";
        var user = await CreateTestUser(currentPassword, hasChangedPassword: true);

        var (success, errorMessage) = await _sut.ChangePasswordAsync(user.Id, currentPassword, newPassword);

        success.Should().BeTrue();
        errorMessage.Should().BeNull();
    }

    [Fact]
    public void WhenHashingPasswordThenProducesDifferentHashesForSamePassword()
    {
        var password = "TestPassword123!";

        var hash1 = _sut.HashPassword(password);
        var hash2 = _sut.HashPassword(password);

        // Hashes should be different due to random salt
        hash1.Should().NotBe(hash2);

        // But both should verify correctly
        _sut.VerifyPassword(password, hash1).Should().BeTrue();
        _sut.VerifyPassword(password, hash2).Should().BeTrue();
    }

    [Fact]
    public void WhenVerifyingPasswordWithWrongPasswordThenReturnsFalse()
    {
        var correctPassword = "CorrectPassword123!";
        var wrongPassword = "WrongPassword123!";
        var hash = _sut.HashPassword(correctPassword);

        _sut.VerifyPassword(wrongPassword, hash).Should().BeFalse();
    }

    private async Task<User> CreateTestUser(string password, bool hasChangedPassword = false)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = $"test-{Guid.NewGuid()}@example.com",
            PasswordHash = _sut.HashPassword(password),
            Role = UserRole.Editor,
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            HasChangedPassword = hasChangedPassword,
            AuthenticationProvider = AuthenticationProvider.BuiltIn
        };

        return await _userRepository.CreateAsync(user);
    }
}

