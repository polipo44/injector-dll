import argparse
import ctypes
import ctypes.wintypes
import os
import sys

# --- Windows API Constants ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_DEBUG_NAME = "SeDebugPrivilege"
SE_PRIVILEGE_ENABLED = 0x00000002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = -1
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

# --- Windows API Structures ---
class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD),
                ("HighPart", ctypes.wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID),
                ("Attributes", ctypes.wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.wintypes.DWORD),
                ("cntUsage", ctypes.wintypes.DWORD),
                ("th32ProcessID", ctypes.wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.wintypes.ULONG)),
                ("th32ModuleID", ctypes.wintypes.DWORD),
                ("cntThreads", ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase", ctypes.wintypes.LONG),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260)]

# --- Windows API Setup ---
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

# Function prototypes
kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.wintypes.LPVOID

kernel32.WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = ctypes.wintypes.BOOL

kernel32.GetModuleHandleW.argtypes = [ctypes.wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = ctypes.wintypes.HMODULE

kernel32.GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.c_char_p]
kernel32.GetProcAddress.restype = ctypes.wintypes.LPVOID

kernel32.CreateRemoteThread.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.LPVOID, ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
kernel32.CreateRemoteThread.restype = ctypes.wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
kernel32.WaitForSingleObject.restype = ctypes.wintypes.DWORD

kernel32.GetExitCodeThread.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD)]
kernel32.GetExitCodeThread.restype = ctypes.wintypes.BOOL

kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE

kernel32.Process32First.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32First.restype = ctypes.wintypes.BOOL

kernel32.Process32Next.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype = ctypes.wintypes.BOOL

psapi.EnumProcessModules.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.HMODULE), ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
psapi.EnumProcessModules.restype = ctypes.wintypes.BOOL

psapi.GetModuleBaseNameW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HMODULE, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = ctypes.wintypes.DWORD

psapi.GetModuleFileNameExW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HMODULE, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD]
psapi.GetModuleFileNameExW.restype = ctypes.wintypes.DWORD

advapi32.OpenProcessToken.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = ctypes.wintypes.BOOL

advapi32.LookupPrivilegeValueW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = ctypes.wintypes.BOOL

advapi32.AdjustTokenPrivileges.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(ctypes.wintypes.DWORD)]
advapi32.AdjustTokenPrivileges.restype = ctypes.wintypes.BOOL

user32.FindWindowW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR]
user32.FindWindowW.restype = ctypes.wintypes.HWND

user32.GetWindowThreadProcessId.argtypes = [ctypes.wintypes.HWND, ctypes.POINTER(ctypes.wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = ctypes.wintypes.DWORD

kernel32.GetFullPathNameW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.LPWSTR, ctypes.POINTER(ctypes.wintypes.LPWSTR)]
kernel32.GetFullPathNameW.restype = ctypes.wintypes.DWORD


# --- Core Logic (1:1 C++ Translation) ---

def get_se_debug_privilege():
    """Gives the current process the SeDebugPrivilege so we can get the required process handle."""
    token = ctypes.wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)):
        raise RuntimeError("Could not open process token.")
    
    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        raise RuntimeError("Could not look up privilege value for SeDebugName.")
    
    privileges = TOKEN_PRIVILEGES()
    privileges.PrivilegeCount = 1
    privileges.Privileges[0].Luid = luid
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    
    if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), ctypes.sizeof(privileges), None, None):
        raise RuntimeError("Could not adjust token privileges.")
    
    kernel32.CloseHandle(token)

def get_process_id_by_name(name: str, case_sensitive: bool = False) -> int:
    """Get process ID via name using CreateToolhelp32Snapshot."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise RuntimeError("Could not get process snapshot.")
    
    proc_entry = PROCESSENTRY32()
    proc_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    
    found = False
    if kernel32.Process32First(snap, ctypes.byref(proc_entry)):
        while True:
            current_process = proc_entry.szExeFile.decode('utf-8', errors='ignore')
            search_name = name if case_sensitive else name.lower()
            current_process = current_process if case_sensitive else current_process.lower()
            
            if current_process == search_name:
                found = True
                break
            
            if not kernel32.Process32Next(snap, ctypes.byref(proc_entry)):
                break
    
    kernel32.CloseHandle(snap)
    
    if not found:
        raise RuntimeError(f"Could not find process: {name}")
    
    return proc_entry.th32ProcessID

def get_process_id_by_window(name: str) -> int:
    """Get process id from window name."""
    hwnd = user32.FindWindowW(None, name)
    if not hwnd:
        raise RuntimeError(f"Could not find window: {name}")
    
    proc_id = ctypes.wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc_id))
    if not proc_id.value:
        raise RuntimeError("Could not get process id from window.")
    
    return proc_id.value

def resolve_path(module_name: str) -> str:
    """Resolve and validate a module path. Handles both relative and absolute paths."""
    # First: canonicalize against CWD
    abs_path = os.path.abspath(module_name)
    if os.path.exists(abs_path):
        return abs_path
    
    # Fallback: resolve relative to the injector script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fallback_path = os.path.join(script_dir, module_name)
    if os.path.exists(fallback_path):
        return os.path.abspath(fallback_path)
        
    raise RuntimeError(f"Could not find module. Path: '{module_name}'")

def get_module_base_address(process_handle: int, path: str) -> int:
    """Check if a module is injected via process handle, and return the base address."""
    buffer = ctypes.create_unicode_buffer(260)
    kernel32.GetFullPathNameW(path, 260, buffer, None)
    search_path = buffer.value.lower()
    
    filename = os.path.basename(search_path)
    
    modules = (ctypes.wintypes.HMODULE * 1024)()
    size_needed = ctypes.wintypes.DWORD()
    
    if not psapi.EnumProcessModules(process_handle, modules, ctypes.sizeof(modules), ctypes.byref(size_needed)):
        raise RuntimeError("Could not get module snapshot for remote process.")
    
    num_modules = size_needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
    
    for i in range(num_modules):
        module = modules[i]
        module_name_buf = ctypes.create_unicode_buffer(260)
        exe_path_buf = ctypes.create_unicode_buffer(260)
        
        psapi.GetModuleBaseNameW(process_handle, module, module_name_buf, 260)
        psapi.GetModuleFileNameExW(process_handle, module, exe_path_buf, 260)
        
        if module_name_buf.value.lower() == filename or exe_path_buf.value.lower() == search_path:
            return module
    
    return 0

def inject_lib(proc_id: int, path: str):
    """Injects a module (fully qualified path) via process id."""
    abs_path = resolve_path(path)
    
    process_handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        False, proc_id
    )
    if not process_handle:
        raise RuntimeError("Could not get handle to process.")
    
    try:
        path_bytes = abs_path.encode('utf-16-le') + b'\x00\x00'
        size = len(path_bytes)
        
        lib_file_remote = kernel32.VirtualAllocEx(process_handle, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not lib_file_remote:
            raise RuntimeError("Could not allocate memory in remote process.")
        
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(process_handle, lib_file_remote, path_bytes, size, ctypes.byref(written)):
            raise RuntimeError("Could not write to memory in remote process.")
        
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        if not h_kernel32:
            raise RuntimeError("Could not get handle to Kernel32.")
        
        load_lib_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
        if not load_lib_addr:
            raise RuntimeError("Could not get pointer to LoadLibraryW.")
        
        thread_handle = kernel32.CreateRemoteThread(
            process_handle, None, 0, load_lib_addr, lib_file_remote, 0, None
        )
        if not thread_handle:
            raise RuntimeError("Could not create thread in remote process.")
        
        kernel32.WaitForSingleObject(thread_handle, INFINITE)
        
        if not get_module_base_address(process_handle, abs_path):
            raise RuntimeError("Call to LoadLibraryW in remote process failed.")
            
        print(f"[+] Successfully injected {os.path.basename(abs_path)} into PID {proc_id}")
        
    finally:
        kernel32.CloseHandle(process_handle)

def eject_lib(proc_id: int, path: str):
    """Ejects a module (fully qualified path) via process id."""
    abs_path = resolve_path(path)
    
    process_handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION,
        False, proc_id
    )
    if not process_handle:
        raise RuntimeError("Could not get handle to process.")
    
    try:
        base_address = get_module_base_address(process_handle, abs_path)
        if not base_address:
            raise RuntimeError("Could not find module in remote process.")
        
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        if not h_kernel32:
            raise RuntimeError("Could not get handle to Kernel32.")
        
        free_lib_addr = kernel32.GetProcAddress(h_kernel32, b"FreeLibrary")
        if not free_lib_addr:
            raise RuntimeError("Could not get pointer to FreeLibrary.")
        
        thread_handle = kernel32.CreateRemoteThread(
            process_handle, None, 0, free_lib_addr, ctypes.c_void_p(base_address), 0, None
        )
        if not thread_handle:
            raise RuntimeError("Could not create thread in remote process.")
        
        kernel32.WaitForSingleObject(thread_handle, INFINITE)
        
        exit_code = ctypes.wintypes.DWORD(0)
        if not kernel32.GetExitCodeThread(thread_handle, ctypes.byref(exit_code)):
            raise RuntimeError("Could not get thread exit code.")
        
        if not exit_code.value:
            raise RuntimeError("Call to FreeLibrary in remote process failed.")
            
        print(f"[+] Successfully ejected {os.path.basename(abs_path)} from PID {proc_id}")
        
    finally:
        kernel32.CloseHandle(process_handle)


# --- CLI Interface ---

def main():
    parser = argparse.ArgumentParser(description="Python DLL Injector (C++ StealthLib equivalent)")
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-n", "--process-name", help="Identifies the target process by its module name")
    target_group.add_argument("-w", "--window-name", help="Identifies the target process by its main window name")
    target_group.add_argument("-p", "--process-id", type=int, help="Identifies the target process by its PID")
    
    parser.add_argument("-c", "--case-sensitive", action="store_true", help="Makes -n case-sensitive")
    
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-i", "--inject", action="store_true", help="Inject the specified DLL(s)")
    action_group.add_argument("-e", "--eject", action="store_true", help="Eject the specified DLL(s)")
    
    parser.add_argument("dlls", nargs="+", help="Absolute or relative path(s) of the DLL(s) to be in-/ejected")
    
    args = parser.parse_args()
    
    # Acquire SeDebugPrivilege (Requires Administrator)
    try:
        get_se_debug_privilege()
    except Exception as e:
        print(f"WARNING: Could not acquire SeDebugPrivilege. Injection may fail. ({e})")
        print("Tip: Right-click your terminal and select 'Run as administrator'.\n")
    
    # Resolve Target PID
    try:
        if args.process_id:
            pid = args.process_id
        elif args.process_name:
            pid = get_process_id_by_name(args.process_name, args.case_sensitive)
        elif args.window_name:
            pid = get_process_id_by_window(args.window_name)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
        
    print(f"Target resolved to PID: {pid}\n")
    
    success_count = 0
    for dll in args.dlls:
        try:
            if args.inject:
                inject_lib(pid, dll)
                success_count += 1
            elif args.eject:
                eject_lib(pid, dll)
                success_count += 1
        except Exception as e:
            print(f"[-] Failed: {e}")
            
    print(f"\nCompleted: {success_count}/{len(args.dlls)} operations successful.")
    sys.exit(0 if success_count == len(args.dlls) else 1)

if __name__ == "__main__":
    # Ensure script is run as admin for best results
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("WARNING: Not running as Administrator. Injection will likely fail.\n")
    main()