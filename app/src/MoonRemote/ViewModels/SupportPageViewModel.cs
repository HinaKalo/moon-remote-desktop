using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace MoonRemote.ViewModels;

public sealed partial class SupportPageViewModel : ViewModelBase
{
    [ObservableProperty] private string _generatedCode = string.Empty;
    [ObservableProperty] private string _expiresAt = string.Empty;
    [ObservableProperty] private string _enterCode = string.Empty;
    [ObservableProperty] private string _statusMessage = "Share your screen with a one-time 12-digit code, or enter a code to assist someone.";
    [ObservableProperty] private bool _isBusy;

    [RelayCommand]
    private async Task GenerateCodeAsync()
    {
        IsBusy = true;
        try
        {
            var resp = await AppServices.Api.CreateSupportCodeAsync();
            GeneratedCode = resp.Code;
            ExpiresAt = resp.ExpiresAt;
            StatusMessage = "One-time support code active for 5 minutes. You will be asked to confirm before anyone connects.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Could not create support code: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task RedeemCodeAsync()
    {
        var code = new string(EnterCode.Where(char.IsAsciiDigit).ToArray());
        if (code.Length != 12)
        {
            StatusMessage = "Support code must be 12 digits.";
            return;
        }
        IsBusy = true;
        try
        {
            var resp = await AppServices.Api.RedeemSupportCodeAsync(code);
            StatusMessage = $"Connected to support session {resp.Session} ({resp.HostName}). Waiting for host confirmation...";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Redeem failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }
}
