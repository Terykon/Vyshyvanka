using System.Net.Http.Json;
using Microsoft.AspNetCore.Components;
using Vyshyvanka.Contracts.Auth;
using Vyshyvanka.Designer.Services;

namespace Vyshyvanka.Designer.Pages;

public partial class Login
{
    [Inject]
    private AuthService AuthService { get; set; } = null!;

    [Inject]
    private NavigationManager Navigation { get; set; } = null!;

    [Inject]
    private HttpClient Http { get; set; } = null!;

    private readonly LoginModel _model = new();
    private string? _errorMessage;
    private bool _isLoading;
    private bool _showDevCredentials;

    protected override async Task OnInitializedAsync()
    {
        if (AuthService.IsAuthenticated)
        {
            Navigation.NavigateTo("/");
            return;
        }

        await LoadAuthConfigAsync();
    }

    private async Task LoadAuthConfigAsync()
    {
        try
        {
            var config = await Http.GetFromJsonAsync<AuthConfigResponse>("api/auth/config");
            _showDevCredentials = config?.ShowDevCredentials ?? false;
        }
        catch
        {
            // If we can't reach the API, don't show dev credentials
            _showDevCredentials = false;
        }
    }

    private async Task HandleLogin()
    {
        _errorMessage = null;
        _isLoading = true;

        try
        {
            var (success, error) = await AuthService.LoginAsync(_model.Email, _model.Password);

            if (success)
            {
                Navigation.NavigateTo("/");
            }
            else
            {
                _errorMessage = error ?? "Login failed";
            }
        }
        finally
        {
            _isLoading = false;
        }
    }

    private class LoginModel
    {
        public string Email { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;
    }

    private void PrefillCredentials(string role)
    {
        (_model.Email, _model.Password) = role switch
        {
            "admin" => ("admin@vyshyvanka.local", "Admin123!"),
            "editor" => ("editor@vyshyvanka.local", "Editor123!"),
            "viewer" => ("viewer@vyshyvanka.local", "Viewer123!"),
            _ => (_model.Email, _model.Password)
        };
        _errorMessage = null;
    }
}
