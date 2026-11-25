using Avalonia.Controls;
using Avalonia.Interactivity;

namespace MoonRemote.Views;

public partial class SendTextWindow : Window
{
    private readonly Func<string, bool>? _sendText;

    public SendTextWindow()
    {
        InitializeComponent();
        Opened += (_, _) => TextToSend.Focus();
        TextToSend.TextChanged += (_, _) => SendButton.IsEnabled = TextToSend.Text is { Length: > 0 };
    }

    public SendTextWindow(Func<string, bool> sendText) : this() => _sendText = sendText;

    private void OnSend(object? sender, RoutedEventArgs e)
    {
        if (TextToSend.Text is not { Length: > 0 } text) return;
        if (_sendText?.Invoke(text) == true) Close();
        else SendError.IsVisible = true;
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close();
}
