"""
memory.py — Windows process memory utilities via NtDll + Kernel32.
Wraps NtReadVirtualMemory / NtWriteVirtualMemory for low-level access.
"""

import ctypes
import ctypes.wintypes as wintypes
import logging
import time
from ctypes import POINTER, Structure, byref, c_size_t, c_ulong, c_void_p, sizeof, windll
from typing import Optional, Tuple

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

PROCESS_ALL_ACCESS    = 0x1F0FFF
TH32CS_SNAPPROCESS    = 0x00000002
TH32CS_SNAPMODULE     = 0x00000008
TH32CS_SNAPMODULE32   = 0x00000010

# FFlag struct defaults
FFLAG_STRUCT_SIZE     = 0xD0
FFLAG_STRING_BUF_OFF  = 0x00  # offset to buffer ptr inside string instance
FFLAG_STRING_LEN_OFF  = 0x08  # offset to length field
FFLAG_STRING_CAP_OFF  = 0x10  # offset to capacity field

INVALID_HANDLE        = -1


# ──────────────────────────────────────────────
# C Structures
# ──────────────────────────────────────────────

class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   POINTER(c_ulong)),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        wintypes.DWORD),
        ("th32ModuleID",  wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage",  wintypes.DWORD),
        ("ProccntUsage",  wintypes.DWORD),
        ("modBaseAddr",   POINTER(ctypes.c_byte)),
        ("modBaseSize",   wintypes.DWORD),
        ("hModule",       wintypes.HMODULE),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]


# ──────────────────────────────────────────────
# Exceptions
# ──────────────────────────────────────────────

class MemoryError(Exception):
    """Raised when a memory read/write operation fails."""

class ProcessNotFoundError(Exception):
    """Raised when the target process cannot be located."""

class ModuleNotFoundError(Exception):
    """Raised when the target module cannot be found in a process."""

class AttachTimeoutError(Exception):
    """Raised when attach_process exceeds the given timeout."""

class StringCapacityError(Exception):
    """Raised when the new string value exceeds the in-process buffer capacity."""


# ──────────────────────────────────────────────
# Low-level NT memory I/O
# ──────────────────────────────────────────────

class NtMemory:
    """
    Thin wrapper around NtReadVirtualMemory / NtWriteVirtualMemory.
    Prefer these over the Kernel32 equivalents to avoid certain
    user-mode hooks that target ReadProcessMemory/WriteProcessMemory.
    """

    NT_SUCCESS = 0

    def __init__(self) -> None:
        ntdll = ctypes.WinDLL("ntdll.dll")

        self._read = ntdll.NtReadVirtualMemory
        self._read.argtypes = [
            wintypes.HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
        ]
        self._read.restype = ctypes.c_long

        self._write = ntdll.NtWriteVirtualMemory
        self._write.argtypes = [
            wintypes.HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
        ]
        self._write.restype = ctypes.c_long

    # ── raw bytes ──────────────────────────────

    def read(self, handle: int, address: int, size: int) -> bytes:
        """Read *size* bytes from *address* in the target process.

        Raises MemoryError on failure.
        """
        buf = ctypes.create_string_buffer(size)
        n   = c_size_t(0)
        status = self._read(handle, c_void_p(address), buf, size, byref(n))
        if status != self.NT_SUCCESS:
            raise MemoryError(
                f"NtReadVirtualMemory failed: status=0x{status & 0xFFFFFFFF:08X} "
                f"addr=0x{address:X} size={size}"
            )
        return buf.raw[: n.value]

    def write(self, handle: int, address: int, data: bytes) -> None:
        """Write *data* to *address* in the target process.

        Raises MemoryError on failure.
        """
        buf    = ctypes.create_string_buffer(data)
        n      = c_size_t(0)
        status = self._write(handle, c_void_p(address), buf, len(data), byref(n))
        if status != self.NT_SUCCESS or n.value != len(data):
            raise MemoryError(
                f"NtWriteVirtualMemory failed: status=0x{status & 0xFFFFFFFF:08X} "
                f"addr=0x{address:X} written={n.value}/{len(data)}"
            )

    # ── typed helpers ──────────────────────────

    def read_i32(self, handle: int, address: int) -> int:
        return int.from_bytes(self.read(handle, address, 4), "little", signed=True)

    def read_u32(self, handle: int, address: int) -> int:
        return int.from_bytes(self.read(handle, address, 4), "little")

    def read_i64(self, handle: int, address: int) -> int:
        return int.from_bytes(self.read(handle, address, 8), "little", signed=True)

    def read_u64(self, handle: int, address: int) -> int:
        return int.from_bytes(self.read(handle, address, 8), "little")

    def write_i32(self, handle: int, address: int, value: int) -> None:
        self.write(handle, address, value.to_bytes(4, "little", signed=True))

    def write_i64(self, handle: int, address: int, value: int) -> None:
        self.write(handle, address, value.to_bytes(8, "little", signed=True))


# ──────────────────────────────────────────────
# Process / module enumeration
# ──────────────────────────────────────────────

class ProcessManager:
    """Locates processes and modules via Toolhelp32 snapshots."""

    def __init__(self) -> None:
        self._k32 = windll.kernel32

    # ── internal helpers ───────────────────────

    @staticmethod
    def _decode(raw: bytes) -> str:
        return raw.decode("utf-8", errors="ignore").lower()

    def _close(self, handle: int) -> None:
        self._k32.CloseHandle(handle)

    # ── public API ─────────────────────────────

    def find_pid(self, process_name: str) -> int:
        """Return the PID of the first process matching *process_name*.

        Raises ProcessNotFoundError if not found.
        """
        name = process_name.lower()
        snap = self._k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == INVALID_HANDLE:
            raise ProcessNotFoundError(f"Cannot create process snapshot (GLE={self._k32.GetLastError()})")

        entry = PROCESSENTRY32()
        entry.dwSize = sizeof(PROCESSENTRY32)

        try:
            if self._k32.Process32First(snap, byref(entry)):
                while True:
                    if self._decode(entry.szExeFile) == name:
                        return entry.th32ProcessID
                    if not self._k32.Process32Next(snap, byref(entry)):
                        break
        finally:
            self._close(snap)

        raise ProcessNotFoundError(f"Process not found: {process_name!r}")

    def get_module_base(self, pid: int, module_name: str) -> Tuple[int, int]:
        """Return *(base_address, size)* of *module_name* inside *pid*.

        Raises ModuleNotFoundError if not found.
        """
        name = module_name.lower()
        flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
        snap  = self._k32.CreateToolhelp32Snapshot(flags, pid)
        if snap == INVALID_HANDLE:
            raise ModuleNotFoundError(
                f"Cannot create module snapshot for pid={pid} (GLE={self._k32.GetLastError()})"
            )

        entry = MODULEENTRY32()
        entry.dwSize = sizeof(MODULEENTRY32)

        try:
            if self._k32.Module32First(snap, byref(entry)):
                while True:
                    if self._decode(entry.szModule) == name:
                        base = ctypes.cast(entry.modBaseAddr, c_void_p).value
                        return base, entry.modBaseSize
                    if not self._k32.Module32Next(snap, byref(entry)):
                        break
        finally:
            self._close(snap)

        raise ModuleNotFoundError(f"Module not found: {module_name!r} in pid={pid}")

    def open_process(self, pid: int) -> int:
        """Open *pid* with PROCESS_ALL_ACCESS. Returns a valid handle.

        Raises ProcessNotFoundError on failure.
        """
        handle = self._k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not handle:
            raise ProcessNotFoundError(
                f"OpenProcess failed for pid={pid} (GLE={self._k32.GetLastError()})"
            )
        return handle


def close_handle(handle: int) -> None:
    """Safely close a Win32 handle."""
    if handle:
        windll.kernel32.CloseHandle(handle)


# ──────────────────────────────────────────────
# High-level memory manager
# ──────────────────────────────────────────────

class MemoryManager:
    """
    High-level façade: attach to a process and manipulate FFlag structs.

    Usage::

        mm = MemoryManager()
        handle, base, size = mm.attach("RobloxPlayerBeta.exe", "RobloxPlayerBeta.exe")
        mm.write_fflag_int(handle, base + OFFSET, VALUE_PTR_OFFSET, 1)
        close_handle(handle)
    """

    def __init__(self) -> None:
        self.mem  = NtMemory()
        self.proc = ProcessManager()

    # ── attach ─────────────────────────────────

    def attach(
        self,
        process_name: str,
        module_name:  str,
        poll_interval: float = 1.0,
        timeout:       Optional[float] = None,
    ) -> Tuple[int, int, int]:
        """
        Poll until *process_name* is running and *module_name* is loaded,
        then return *(process_handle, module_base, module_size)*.

        Args:
            process_name:  e.g. ``"game.exe"``
            module_name:   e.g. ``"game.exe"`` or ``"engine.dll"``
            poll_interval: seconds between retries (default 1.0)
            timeout:       give up after this many seconds; raises
                           AttachTimeoutError. None = wait forever.
        """
        deadline = None if timeout is None else time.monotonic() + timeout

        while True:
            try:
                pid    = self.proc.find_pid(process_name)
                handle = self.proc.open_process(pid)
                try:
                    base, size = self.proc.get_module_base(pid, module_name)
                    log.info("Attached to %r pid=%d base=0x%X size=0x%X", process_name, pid, base, size)
                    return handle, base, size
                except ModuleNotFoundError:
                    close_handle(handle)
            except (ProcessNotFoundError, ModuleNotFoundError) as exc:
                log.debug("Waiting for process: %s", exc)

            if deadline is not None and time.monotonic() >= deadline:
                raise AttachTimeoutError(
                    f"Could not attach to {process_name!r} within {timeout}s"
                )
            time.sleep(poll_interval)

    # ── internal: read fflag struct ────────────

    def _read_fflag_struct(
        self,
        handle:           int,
        fflag_addr:       int,
        struct_size:      int = FFLAG_STRUCT_SIZE,
    ) -> bytes:
        data = self.mem.read(handle, fflag_addr, struct_size)
        if len(data) < struct_size:
            raise MemoryError(
                f"Short read of FFlag struct at 0x{fflag_addr:X}: "
                f"got {len(data)} bytes, expected {struct_size}"
            )
        return data

    def _extract_ptr(self, struct_data: bytes, offset: int) -> int:
        ptr = int.from_bytes(struct_data[offset: offset + 8], "little")
        if not ptr:
            raise MemoryError(f"Null pointer at struct offset 0x{offset:X}")
        return ptr

    # ── fflag writers ──────────────────────────

    def write_fflag_int(
        self,
        handle:          int,
        fflag_addr:      int,
        value_ptr_offset: int,
        value:           int,
        struct_size:     int = FFLAG_STRUCT_SIZE,
    ) -> None:
        """
        Write a 32-bit integer FFlag value.

        The FFlag struct at *fflag_addr* contains a pointer at
        *value_ptr_offset* that points to the actual int32 storage.

        Raises MemoryError on any failure.
        """
        struct    = self._read_fflag_struct(handle, fflag_addr, struct_size)
        value_ptr = self._extract_ptr(struct, value_ptr_offset)
        self.mem.write_i32(handle, value_ptr, value)
        log.debug("write_fflag_int  addr=0x%X offset=0x%X value=%d", fflag_addr, value_ptr_offset, value)

    def write_fflag_string(
        self,
        handle:          int,
        fflag_addr:      int,
        value_ptr_offset: int,
        value:           str,
        struct_size:     int = FFLAG_STRUCT_SIZE,
    ) -> None:
        """
        Write a UTF-8 string FFlag value.

        Layout assumed inside the string instance pointed to by the
        struct field at *value_ptr_offset*:
          +0x00  uint64  buffer_ptr   (pointer to char[] data)
          +0x08  uint64  length
          +0x10  uint64  capacity

        Raises StringCapacityError if the encoded value exceeds the
        existing in-process buffer capacity.
        Raises MemoryError on any I/O failure.
        """
        struct    = self._read_fflag_struct(handle, fflag_addr, struct_size)
        inst_ptr  = self._extract_ptr(struct, value_ptr_offset)

        buf_ptr  = self.mem.read_u64(handle, inst_ptr + FFLAG_STRING_BUF_OFF)
        capacity = self.mem.read_u64(handle, inst_ptr + FFLAG_STRING_CAP_OFF)

        encoded = value.encode("utf-8")
        new_len = len(encoded)

        if new_len > capacity:
            raise StringCapacityError(
                f"New value ({new_len} bytes) exceeds buffer capacity ({capacity} bytes)"
            )

        self.mem.write(handle, buf_ptr, encoded + b"\x00")
        self.mem.write_i64(handle, inst_ptr + FFLAG_STRING_LEN_OFF, new_len)
        log.debug(
            "write_fflag_string addr=0x%X offset=0x%X value=%r len=%d cap=%d",
            fflag_addr, value_ptr_offset, value, new_len, capacity,
        )