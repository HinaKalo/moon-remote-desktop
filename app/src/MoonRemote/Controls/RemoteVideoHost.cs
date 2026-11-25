using System.Runtime.InteropServices;
using Avalonia.Controls;
using Avalonia.Platform;

namespace MoonRemote.Controls;

/// <summary>
/// Hosts a native Win32 child HWND so `moonrd_ffi.dll` can attach a D3D11 flip-model
/// swapchain and present decoded H.264 frames with zero copy.
/// </summary>
public sealed unsafe partial class RemoteVideoHost : NativeControlHost
{
    public nint NativeHwnd { get; private set; }
    public event Action<nint>? HwndReady;


    public event Action<uint, uint, int, bool, int, int>? VideoPointer;
    private GCHandle _instance;
    private int _buttons;
    private uint _lastX, _lastY;
    private bool _forwardMouse;

    public bool ForwardMouse
    {
        get => _forwardMouse;
        set
        {
            _forwardMouse = value;
            if (!value) ReleasePointer();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct Point { public int X, Y; }

    [LibraryImport("comctl32.dll")]
    private static partial int SetWindowSubclass(nint hwnd, delegate* unmanaged[Stdcall]<nint, uint, nuint, nint, nuint, nuint, nint> proc, nuint id, nuint data);
    [LibraryImport("comctl32.dll")]
    private static partial int RemoveWindowSubclass(nint hwnd, delegate* unmanaged[Stdcall]<nint, uint, nuint, nint, nuint, nuint, nint> proc, nuint id);
    [LibraryImport("comctl32.dll")]
    private static partial nint DefSubclassProc(nint hwnd, uint msg, nuint wParam, nint lParam);
    [LibraryImport("user32.dll")]
    private static partial int GetClientRect(nint hwnd, out Rect rect);
    [LibraryImport("user32.dll")]
    private static partial int ScreenToClient(nint hwnd, ref Point point);
    [LibraryImport("user32.dll")]
    private static partial nint SetCapture(nint hwnd);
    [LibraryImport("user32.dll")]
    private static partial nint GetCapture();
    [LibraryImport("user32.dll")]
    private static partial int ReleaseCapture();

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvStdcall)])]
    private static nint VideoProc(nint hwnd, uint msg, nuint keys, nint position, nuint id, nuint data)
    {
        // STATIC controls normally return HTTRANSPARENT. This child owns the video pixels
        // and must receive their input even when hosted inside Avalonia's native container.
        if (msg == 0x0084) return 1; // WM_NCHITTEST -> HTCLIENT
        var host = (RemoteVideoHost)GCHandle.FromIntPtr((nint)data).Target!;
        if (msg == 0x0215) host.ReleaseButtons(); // WM_CAPTURECHANGED
        if (host.ForwardMouse && msg is >= 0x0200 and <= 0x020E && host.HandleMouse(hwnd, msg, keys, position))
            return 0;
        return DefSubclassProc(hwnd, msg, keys, position);
    }

    private bool HandleMouse(nint hwnd, uint msg, nuint keys, nint position)
    {
        var point = new Point { X = (short)(long)position, Y = (short)((long)position >> 16) };
        bool wheel = msg is 0x020A or 0x020E;
        if (wheel && ScreenToClient(hwnd, ref point) == 0) return false;
        if (GetClientRect(hwnd, out var rect) == 0 || rect.Right < 2 || rect.Bottom < 2) return false;
        _lastX = (uint)(Math.Clamp(point.X, 0, rect.Right - 1) * 65535L / (rect.Right - 1));
        _lastY = (uint)(Math.Clamp(point.Y, 0, rect.Bottom - 1) * 65535L / (rect.Bottom - 1));
        int button = msg switch
        {
            >= 0x0201 and <= 0x0203 => 1, // left down/up/double-click
            >= 0x0204 and <= 0x0206 => 2, // right
            >= 0x0207 and <= 0x0209 => 3, // middle
            >= 0x020B and <= 0x020D => ((keys >> 16) & 0xffff) == 1 ? 4 : 5,
            _ => 0,
        };
        bool pressed = button != 0 && msg is not (0x0202 or 0x0205 or 0x0208 or 0x020C);
        if (button != 0)
        {
            if (pressed)
            {
                if (GetCapture() != hwnd) SetCapture(hwnd);
                _buttons |= 1 << button;
            }
            else { _buttons &= ~(1 << button); }
        }
        int delta = (short)(keys >> 16);
        VideoPointer?.Invoke(_lastX, _lastY, button, pressed, msg == 0x020E ? delta : 0, msg == 0x020A ? delta : 0);
        if (button != 0 && !pressed && _buttons == 0 && GetCapture() == hwnd) ReleaseCapture();
        return true;
    }

    private void ReleaseButtons()
    {
        var buttons = _buttons;
        _buttons = 0;
        for (int button = 1; button <= 5; button++)
            if ((buttons & (1 << button)) != 0) VideoPointer?.Invoke(_lastX, _lastY, button, false, 0, 0);
    }

    public void ReleasePointer()
    {
        ReleaseButtons();
        if (NativeHwnd != 0 && GetCapture() == NativeHwnd) ReleaseCapture();
    }
    [LibraryImport("user32.dll", EntryPoint = "CreateWindowExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateWindowExW(
        uint exStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        nint parent,
        nint menu,
        nint instance,
        nint param);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyWindow(nint hwnd);

    protected override IPlatformHandle CreateNativeControlCore(IPlatformHandle parent)
    {
        if (OperatingSystem.IsWindows())
        {
            const uint WS_CHILD = 0x40000000;
            const uint WS_VISIBLE = 0x10000000;
            const uint WS_CLIPSIBLINGS = 0x04000000;
            var hwnd = CreateWindowExW(
                0,
                "STATIC",
                string.Empty,
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                0,
                0,
                800,
                600,
                parent.Handle,
                0,
                0,
                0);
            if (hwnd == 0) throw new System.ComponentModel.Win32Exception();
            _instance = GCHandle.Alloc(this);
            if (SetWindowSubclass(hwnd, &VideoProc, 1, (nuint)GCHandle.ToIntPtr(_instance)) == 0)
            {
                _instance.Free();
                DestroyWindow(hwnd);
                throw new InvalidOperationException("Cannot attach input to the video surface.");
            }
            NativeHwnd = hwnd;
            HwndReady?.Invoke(hwnd);
            return new PlatformHandle(hwnd, "HWND");
        }
        return base.CreateNativeControlCore(parent);
    }

    protected override void DestroyNativeControlCore(IPlatformHandle control)
    {
        if (OperatingSystem.IsWindows() && control.Handle != 0)
        {
            ReleaseButtons();
            RemoveWindowSubclass(control.Handle, &VideoProc, 1);
            _instance.Free();
            DestroyWindow(control.Handle);
            NativeHwnd = 0;
            return;
        }
        base.DestroyNativeControlCore(control);
    }
}
