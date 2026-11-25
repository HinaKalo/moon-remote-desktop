using System.Reflection;
using System.Runtime.InteropServices;
using Avalonia.Platform;
using MoonRemote.Controls;
using Xunit;

namespace MoonRemote.Tests;

public sealed class VideoPointerTests
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern nint CreateWindowEx(int ex, string cls, string title, uint style, int x, int y,
        int width, int height, nint parent, nint menu, nint instance, nint data);
    [DllImport("user32.dll")]
    private static extern nint SendMessage(nint hwnd, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll")]
    private static extern bool DestroyWindow(nint hwnd);

    [Fact]
    public void VideoChildForwardsMouseAndReleasesCapturedButtons()
    {
        if (!OperatingSystem.IsWindows()) return;
        var parent = CreateWindowEx(0, "STATIC", "", 0, 0, 0, 800, 600, 0, 0, 0, 0);
        Assert.NotEqual(0, parent);
        var surface = new RemoteVideoHost { ForwardMouse = true };
        const BindingFlags hooks = BindingFlags.Instance | BindingFlags.NonPublic;
        var create = typeof(RemoteVideoHost).GetMethod("CreateNativeControlCore", hooks)!;
        var destroy = typeof(RemoteVideoHost).GetMethod("DestroyNativeControlCore", hooks)!;
        IPlatformHandle? handle = null;
        try
        {
            var events = new List<(uint X, uint Y, int Button, bool Pressed, int WheelX, int WheelY)>();
            surface.VideoPointer += (x, y, button, pressed, wheelX, wheelY) => events.Add((x, y, button, pressed, wheelX, wheelY));
            handle = (IPlatformHandle)create.Invoke(surface, [new PlatformHandle(parent, "HWND")])!;
            nint point = (150 << 16) | 400;
            Assert.Equal((nint)1, SendMessage(handle.Handle, 0x84, 0, point)); // HTCLIENT
            SendMessage(handle.Handle, 0x200, 0, point); // move
            SendMessage(handle.Handle, 0x204, 2, point); // right down
            SendMessage(handle.Handle, 0x205, 0, point); // right up
            SendMessage(handle.Handle, 0x20A, 120 << 16, point);
            SendMessage(handle.Handle, 0x201, 1, point); // begin a drag, then lose capture
            SendMessage(handle.Handle, 0x215, 0, 0);
            Assert.Equal(6, events.Count);
            Assert.Equal((32808u, 16411u, 0, false, 0, 0), events[0]);
            Assert.Equal((32808u, 16411u, 2, true, 0, 0), events[1]);
            Assert.Equal((32808u, 16411u, 2, false, 0, 0), events[2]);
            Assert.Equal(120, events[3].WheelY);
            Assert.Equal((32808u, 16411u, 1, false, 0, 0), events[5]);

            SendMessage(handle.Handle, 0x201, 1, point);
            var beforeDisable = events.Count;
            surface.ForwardMouse = false;
            Assert.Equal((32808u, 16411u, 1, false, 0, 0), Assert.Single(events.Skip(beforeDisable)));
            var afterDisable = events.Count;
            SendMessage(handle.Handle, 0x200, 0, point);
            SendMessage(handle.Handle, 0x204, 2, point);
            Assert.Equal(afterDisable, events.Count);

            surface.ForwardMouse = true;
            SendMessage(handle.Handle, 0x200, 0, point);
            Assert.Equal(afterDisable + 1, events.Count);
        }
        finally
        {
            if (handle != null) destroy.Invoke(surface, [handle]);
            DestroyWindow(parent);
        }
    }
}
