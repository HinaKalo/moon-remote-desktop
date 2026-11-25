using Avalonia.Input;

namespace MoonRemote.Services;

public static class RemoteKeyboard
{
    public static uint HidUsage(PhysicalKey key) => key switch
    {
        >= PhysicalKey.A and <= PhysicalKey.Z => 0x04 + (uint)(key - PhysicalKey.A),
        >= PhysicalKey.Digit1 and <= PhysicalKey.Digit9 => 0x1e + (uint)(key - PhysicalKey.Digit1),
        PhysicalKey.Digit0 => 0x27,
        PhysicalKey.Enter => 0x28,
        PhysicalKey.Escape => 0x29,
        PhysicalKey.Backspace => 0x2a,
        PhysicalKey.Tab => 0x2b,
        PhysicalKey.Space => 0x2c,
        PhysicalKey.Minus => 0x2d,
        PhysicalKey.Equal => 0x2e,
        PhysicalKey.BracketLeft => 0x2f,
        PhysicalKey.BracketRight => 0x30,
        PhysicalKey.Backslash => 0x31,
        PhysicalKey.Semicolon => 0x33,
        PhysicalKey.Quote => 0x34,
        PhysicalKey.Backquote => 0x35,
        PhysicalKey.Comma => 0x36,
        PhysicalKey.Period => 0x37,
        PhysicalKey.Slash => 0x38,
        PhysicalKey.CapsLock => 0x39,
        >= PhysicalKey.F1 and <= PhysicalKey.F12 => 0x3a + (uint)(key - PhysicalKey.F1),
        PhysicalKey.PrintScreen => 0x46,
        PhysicalKey.ScrollLock => 0x47,
        PhysicalKey.Insert => 0x49,
        PhysicalKey.Home => 0x4a,
        PhysicalKey.PageUp => 0x4b,
        PhysicalKey.Delete => 0x4c,
        PhysicalKey.End => 0x4d,
        PhysicalKey.PageDown => 0x4e,
        PhysicalKey.ArrowRight => 0x4f,
        PhysicalKey.ArrowLeft => 0x50,
        PhysicalKey.ArrowDown => 0x51,
        PhysicalKey.ArrowUp => 0x52,
        PhysicalKey.ControlLeft => 0xe0,
        PhysicalKey.ShiftLeft => 0xe1,
        PhysicalKey.AltLeft => 0xe2,
        PhysicalKey.MetaLeft => 0xe3,
        PhysicalKey.ControlRight => 0xe4,
        PhysicalKey.ShiftRight => 0xe5,
        PhysicalKey.AltRight => 0xe6,
        PhysicalKey.MetaRight => 0xe7,
        _ => 0,
    };
}
