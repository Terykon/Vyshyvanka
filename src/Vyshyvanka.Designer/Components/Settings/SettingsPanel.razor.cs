using System.Net.Http.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.JSInterop;
using Vyshyvanka.Contracts.Auth;
using Vyshyvanka.Designer.Services;

namespace Vyshyvanka.Designer.Components;

public partial class SettingsPanel : ComponentBase, IDisposable
{
    [Inject] private IJSRuntime Js { get; set; } = null!;

    [Inject] private ThemeService ThemeService { get; set; } = null!;

    [Inject] private HttpClient Http { get; set; } = null!;

    private string? _uploadError;
    private string? _uploadSuccess;

    // Password change state
    private string _authProvider = string.Empty;
    private string _currentPassword = string.Empty;
    private string _newPassword = string.Empty;
    private string _confirmPassword = string.Empty;
    private string? _passwordError;
    private string? _passwordSuccess;
    private bool _isChangingPassword;

    protected override async Task OnInitializedAsync()
    {
        ThemeService.OnThemeChanged += StateHasChanged;
        await LoadAuthConfigAsync();
    }

    private async Task LoadAuthConfigAsync()
    {
        try
        {
            var config = await Http.GetFromJsonAsync<AuthConfigResponse>("api/auth/config");
            _authProvider = config?.Provider ?? "Unknown";
        }
        catch
        {
            _authProvider = "Unknown";
        }
    }

    private async Task ChangePasswordAsync()
    {
        _passwordError = null;
        _passwordSuccess = null;

        if (string.IsNullOrWhiteSpace(_currentPassword) || string.IsNullOrWhiteSpace(_newPassword))
        {
            _passwordError = "Current password and new password are required.";
            return;
        }

        if (_newPassword != _confirmPassword)
        {
            _passwordError = "New password and confirmation do not match.";
            return;
        }

        if (_newPassword.Length < 8)
        {
            _passwordError = "Password must be at least 8 characters.";
            return;
        }

        _isChangingPassword = true;
        StateHasChanged();

        try
        {
            var request = new ChangePasswordRequest
            {
                CurrentPassword = _currentPassword,
                NewPassword = _newPassword
            };

            var response = await Http.PostAsJsonAsync("api/auth/change-password", request);

            if (response.IsSuccessStatusCode)
            {
                _passwordSuccess = "Password changed successfully.";
                _currentPassword = string.Empty;
                _newPassword = string.Empty;
                _confirmPassword = string.Empty;
            }
            else
            {
                var error = await response.Content.ReadFromJsonAsync<ErrorResponse>();
                _passwordError = error?.Error ?? "Failed to change password.";
            }
        }
        catch (Exception ex)
        {
            _passwordError = $"Error: {ex.Message}";
        }
        finally
        {
            _isChangingPassword = false;
        }
    }

    private async Task ApplyTheme(string themeId)
    {
        await ThemeService.SetThemeAsync(themeId);
    }

    private async Task ExportTheme(string themeId)
    {
        var json = ThemeService.ExportThemeJson(themeId);
        if (string.IsNullOrEmpty(json))
        {
            return;
        }

        await Js.InvokeVoidAsync("downloadFile", $"{themeId}.json", json, "application/json");
    }

    private async Task DeleteTheme(string themeId)
    {
        await ThemeService.RemoveThemeAsync(themeId);
    }

    private async Task OnThemeFileSelected(InputFileChangeEventArgs e)
    {
        _uploadError = null;
        _uploadSuccess = null;

        var file = e.File;
        if (file is null)
        {
            return;
        }

        if (file.Size > 100 * 1024)
        {
            _uploadError = "Theme file too large (max 100KB).";
            return;
        }

        try
        {
            using var stream = file.OpenReadStream(maxAllowedSize: 100 * 1024);
            using var reader = new StreamReader(stream);
            var json = await reader.ReadToEndAsync();

            var id = await ThemeService.ImportThemeAsync(json);
            if (id is null)
            {
                _uploadError = "Invalid theme JSON. Ensure it has id, name, baseMode, and colors.";
            }
            else
            {
                _uploadSuccess = $"Theme imported. Switch to \"{id}\" from the selector.";
            }
        }
        catch
        {
            _uploadError = "Failed to read the theme file.";
        }
    }

    public void Dispose()
    {
        ThemeService.OnThemeChanged -= StateHasChanged;
    }

    private record ErrorResponse(string? Error);
}
