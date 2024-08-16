import ctypes
from ctypes.wintypes import DWORD,HANDLE,WORD,LPSTR,LPBYTE

k_handle = ctypes.WinDLL("Kernel32.dll")


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb",DWORD),
        ("lpReserved",LPSTR),
        ("lpDesktop",LPSTR),
        ("lpTitle",LPSTR),
        ("dwX",DWORD),
        ("dwY",DWORD),
        ("dwXSize",DWORD,),
        ("dwYSize",DWORD),
        ("dwXCountChars",DWORD),
        ("dwYCountChars",DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",DWORD),
        ("wShowWindow",WORD),
        ("cbReserved2",WORD),
        ("lpReserved2",LPBYTE),
        ("hStdInput",HANDLE),
        ("hStdOutput",HANDLE),
        ("hStdError",HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",HANDLE),
        ("hThread",HANDLE),
        ("dwProcessId",DWORD),
        ("dwThreadId",DWORD),
    ]

lpApplicationName = "C:\\Windows\\System32\\osk.exe"
lpCommandLine = None
lpProcessAttributes = None
lpThreadAttributes = None
lpEnvironment = None
lpCurrentDirectory = None

dwCreationFlags = 0x00000010
bInheritHandles = False
lpProcessInformation = PROCESS_INFORMATION()
lpStartupInfo = STARTUPINFO()
lpStartupInfo.wShowWindow = 0x1
lpStartupInfo.dwFlags = 0x1

response = k_handle.CreateProcessW(
    lpApplicationName,
    lpCommandLine,
    lpProcessAttributes,
    lpThreadAttributes,
    bInheritHandles,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStartupInfo),
    ctypes.byref(lpProcessInformation))





