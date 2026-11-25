using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Lumen.UI.Controls;

namespace MoonRemote.ViewModels;

public partial class HomePageViewModel : ViewModelBase
{
    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private int _clicks;

    [RelayCommand]
    private void Greet()
    {
        Clicks++;
        Toast.Success(
            string.IsNullOrWhiteSpace(Name) ? "Hello!" : $"Hello, {Name}!",
            $"You clicked {Clicks} time(s).");
    }

    [RelayCommand]
    private async Task ResetAsync()
    {
        if (await Dialog.ConfirmAsync("Reset counter?", "The click counter will go back to zero.", "Reset", isDanger: true))
        {
            Clicks = 0;
            Toast.Info("Counter reset");
        }
    }
}
