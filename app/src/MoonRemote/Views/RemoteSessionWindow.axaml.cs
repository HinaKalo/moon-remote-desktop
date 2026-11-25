using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using MoonRemote.Services;
using MoonRemote.ViewModels;

namespace MoonRemote.Views;

public partial class RemoteSessionWindow : Window
{
    private WindowState _previousState;
    private PhysicalKey _localKeyDown;
    private SendTextWindow? _textDialog;
    private readonly HashSet<uint> _heldKeys = [];
    private RemoteSessionViewModel? _model;
    public RemoteSessionWindow()
    {
        InitializeComponent();
        VideoArea.SizeChanged += (_, _) => FitVideo();
        SizeChanged += (_, e) =>
        {
            bool compact = e.NewSize.Width < 760;
            ShortcutLabel.IsVisible = !compact;
            DisplayPicker.Width = compact ? 113 : 166;
        };
        DataContextChanged += (_, _) =>
        {
            if (_model is not null) _model.PropertyChanged -= OnSessionChanged;
            _model = DataContext as RemoteSessionViewModel;
            if (_model is not null) _model.PropertyChanged += OnSessionChanged;
            FitVideo();
        };
        VideoHost.HwndReady += async hwnd =>
        {
            if (DataContext is RemoteSessionViewModel vm)
                await vm.AttachHwndAndConnectAsync(hwnd);
        };
        Closed += (_, _) =>
        {
            if (_model is null) return;
            _model.PropertyChanged -= OnSessionChanged;
            _model.Dispose();
        };
        VideoHost.VideoPointer += (x, y, button, down, wheelX, wheelY) =>
        {
            if (DataContext is RemoteSessionViewModel vm && vm.InputEnabled)
            {
                if (down && button != 0) VideoHost.Focus();
                vm.SendPointer(x, y, button, down, wheelX, wheelY);
            }
        };
        VideoHost.KeyDown += OnKeyDown;
        VideoHost.KeyUp += OnKeyUp;
        AddHandler(KeyDownEvent, OnLocalShortcut, RoutingStrategies.Tunnel);
        AddHandler(KeyUpEvent, OnLocalShortcutReleased, RoutingStrategies.Tunnel);
        VideoHost.LostFocus += (_, _) => ReleaseRemoteKeys();
        Deactivated += (_, _) =>
        {
            ReleaseRemoteInput();
            if (_textDialog is null) _localKeyDown = PhysicalKey.None;
        };
        Closing += (_, _) => ReleaseRemoteInput();
    }

    private void OnSessionChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (_model is not { } vm) return;
        switch (e.PropertyName)
        {
            case nameof(vm.VideoAspect):
                FitVideo();
                break;
            case nameof(vm.ShowPinPrompt) when vm.ShowPinPrompt:
                Dispatcher.UIThread.Post(() =>
                {
                    if (IsVisible && vm.ShowPinPrompt) PinEntry.Focus();
                }, DispatcherPriority.Input);
                break;
            case nameof(vm.UseControllerMouse):
                VideoHost.ForwardMouse = vm.InputEnabled && vm.UseControllerMouse;
                if (vm.InputEnabled) VideoHost.Focus();
                break;
            case nameof(vm.InputEnabled):
                VideoHost.ForwardMouse = vm.InputEnabled && vm.UseControllerMouse;
                if (vm.InputEnabled) VideoHost.Focus();
                else
                {
                    _heldKeys.Clear();
                    if (_textDialog is { IsVisible: true } open) open.Close();
                    if (WindowState == WindowState.FullScreen) ToggleFullScreen();
                }
                break;
        }
    }

    private void FitVideo()
    {
        double aspect = (DataContext as RemoteSessionViewModel)?.VideoAspect ?? 16d / 9;
        double width = Math.Min(VideoArea.Bounds.Width, VideoArea.Bounds.Height * aspect);
        VideoHost.Width = width;
        VideoHost.Height = width / aspect;
    }

    private void OnFullScreenClick(object? sender, RoutedEventArgs e) => ToggleFullScreen();

    private void ToggleFullScreen()
    {
        bool enter = WindowState != WindowState.FullScreen;
        if (enter) _previousState = WindowState;
        Toolbar.IsVisible = !enter;
        WindowState = enter ? WindowState.FullScreen : _previousState;
        if (_textDialog is null) VideoHost.Focus();
    }

    private void OnDisconnectClick(object? sender, RoutedEventArgs e)
    {
        Close();
    }

    private async void OnTypeTextClick(object? sender, RoutedEventArgs e) => await ShowTextDialogAsync();

    private async Task ShowTextDialogAsync()
    {
        if (_textDialog is not null || !IsVisible || DataContext is not RemoteSessionViewModel { InputEnabled: true } vm) return;
        ReleaseRemoteInput();
        var dialog = new SendTextWindow(vm.SendText);
        _textDialog = dialog;
        try { await dialog.ShowDialog(this); }
        finally
        {
            _textDialog = null;
            _localKeyDown = PhysicalKey.None;
            if (IsVisible && vm.InputEnabled) VideoHost.Focus();
        }
    }

    private async void OnLocalShortcut(object? sender, KeyEventArgs e)
    {
        if (_model is not { InputEnabled: true }) return;
        if (e.PhysicalKey != PhysicalKey.None && e.PhysicalKey == _localKeyDown)
        {
            e.Handled = true;
            return;
        }
        if (e.PhysicalKey == PhysicalKey.Enter && e.KeyModifiers == (KeyModifiers.Control | KeyModifiers.Shift))
        {
            e.Handled = true;
            _localKeyDown = e.PhysicalKey;
            await ShowTextDialogAsync();
            return;
        }
        if (e.KeyModifiers == KeyModifiers.None &&
            (e.PhysicalKey == PhysicalKey.F11 || (e.PhysicalKey == PhysicalKey.Escape && WindowState == WindowState.FullScreen)))
        {
            ToggleFullScreen();
            _localKeyDown = e.PhysicalKey;
            e.Handled = true;
        }
    }

    private void OnLocalShortcutReleased(object? sender, KeyEventArgs e)
    {
        if (e.PhysicalKey == PhysicalKey.None || e.PhysicalKey != _localKeyDown) return;
        _localKeyDown = PhysicalKey.None;
        e.Handled = true;
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (_model is not { InputEnabled: true } vm) return;
        uint usage = RemoteKeyboard.HidUsage(e.PhysicalKey);
        if (usage == 0) return;
        if (vm.SendKey(usage, true)) _heldKeys.Add(usage);
        e.Handled = true;
    }

    private void OnKeyUp(object? sender, KeyEventArgs e)
    {
        uint usage = RemoteKeyboard.HidUsage(e.PhysicalKey);
        if (usage == 0) return;
        if (DataContext is RemoteSessionViewModel vm && _heldKeys.Contains(usage) && vm.SendKey(usage, false))
            _heldKeys.Remove(usage);
        e.Handled = true;
    }

    private void ReleaseRemoteKeys()
    {
        if (DataContext is RemoteSessionViewModel vm)
            _heldKeys.RemoveWhere(usage => vm.SendKey(usage, false));
    }

    private void ReleaseRemoteInput()
    {
        ReleaseRemoteKeys();
        VideoHost.ReleasePointer();
    }
}
