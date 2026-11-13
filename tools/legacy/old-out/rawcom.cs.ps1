Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class RawCom {
    [StructLayout(LayoutKind.Sequential)]
    private struct COMMTIMEOUTS {
        public uint ReadIntervalTimeout;
        public uint ReadTotalTimeoutMultiplier;
        public uint ReadTotalTimeoutConstant;
        public uint WriteTotalTimeoutMultiplier;
        public uint WriteTotalTimeoutConstant;
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint create, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool SetCommTimeouts(IntPtr h, ref COMMTIMEOUTS t);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool ReadFile(IntPtr h, byte[] buf, uint n,
        out uint read, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr h);

    // Returns handle as long: >0 ok, -1 INVALID_HANDLE_VALUE, negative errno else.
    public static long Open(string port) {
        IntPtr h = CreateFileW(@"\\.\" + port, 0x80000000, 0,
            IntPtr.Zero, 3, 0, IntPtr.Zero);
        long v = h.ToInt64();
        if (v == -1)
            return -Marshal.GetLastWin32Error();
        return v;
    }
    public static int SetTimeout(long h, int ms) {
        COMMTIMEOUTS t = new COMMTIMEOUTS();
        t.ReadIntervalTimeout = 0;
        t.ReadTotalTimeoutMultiplier = 0;
        t.ReadTotalTimeoutConstant = (uint)ms;
        bool ok = SetCommTimeouts(new IntPtr(h), ref t);
        return ok ? 0 : -Marshal.GetLastWin32Error();
    }
    // >0 bytes read, 0 timeout, negative errno.
    public static int Read(long h, byte[] buf) {
        uint n = 0;
        bool ok = ReadFile(new IntPtr(h), buf, (uint)buf.Length, out n, IntPtr.Zero);
        if (ok) return (int)n;
        return -Marshal.GetLastWin32Error();
    }
    public static void Close(long h) { CloseHandle(new IntPtr(h)); }
}
"@
