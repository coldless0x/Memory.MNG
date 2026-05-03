# Memory Manager

A C++17 **usermode virtual memory** library for Windows: read, write, allocate, protect, and query regions in the **current process** or in another process opened with `OpenProcess`. Ships with a console demo, **`memory-manager.exe`**, that runs a scripted checklist and prints real addresses, MBI fields, module bases, and API names (handy for validating rights and your setup).

## Repository layout

| File | Role |
|------|------|
| `memory.h` / `memory.cpp` | `memory::manager` — stable API for your code |
| `main.cpp` | Demo: tries `notepad.exe`; if missing or attach fails, runs the same suite on the **local** process |
| `memory.sln` / `memory.vcxproj` | Visual Studio, **x64**, console subsystem |
| `build.bat` | Release x64 build via MSBuild |

## Requirements

- Windows 10 or later, **x64**
- Visual Studio 2022 (or Build Tools) with **Desktop development with C++** and the Windows SDK

## Build

From the project directory:

```bat
build.bat
```

Or manually:

```bat
msbuild memory.sln /p:Configuration=Release /p:Platform=x64
```

Typical output:

```text
x64\Release\memory-manager.exe
```

## Run the demo

1. Optional: start **Notepad** so the program can attach to a remote process (`OpenProcess` with `default_access()`).
2. Run `memory-manager.exe`. It pauses at the end so the console does not vanish immediately.

Behavior:

- If `notepad.exe` is found and **attach** succeeds, the log shows `target : notepad` with a **PID** and uses **ReadProcessMemory** / **WriteProcessMemory** and **Ex** APIs where applicable.
- Otherwise it uses the **local** process (`GetCurrentProcess`) with `memcpy` / `VirtualAlloc` / etc., and the printed labels reflect that (e.g. `memcpy (local write)` instead of WPM).

Output includes concrete samples: pointers from `VirtualAlloc(Ex)`, a test dword, `MEMORY_BASIC_INFORMATION` fields, `kernel32.dll` and main image bases, batch read/write, `mem_copy` / `mem_fill` / `mem_compare`, the first enumerated regions, and `VirtualFree(Ex)`.

## API quick map

| Need | Method(s) | Win32 (remote / local) |
|------|-----------|-------------------------|
| Full read/write | `read`, `write` | RPM / WPM · `memcpy` |
| Partial read/write | `read_partial`, `write_partial` | RPM / WPM (partial) · `memcpy` |
| Reserve / free | `allocate`, `release` | `VirtualAllocEx` / `VirtualFreeEx` · `VirtualAlloc` / `VirtualFree` |
| Page protection | `protect` | `VirtualProtectEx` · `VirtualProtect` |
| MBI query | `query`, `query_mbi` | `VirtualQueryEx` · `VirtualQuery` |
| Module base (UTF-8 name) | `module_base_utf8`, `get_module_base` | `CreateToolhelp32Snapshot` + `Module32*W` |
| Main image base | `main_module_base` | Toolhelp (first module in the walk) |
| Sequential multi read/write | `batch_read`, `batch_write` | Multiple RPM / WPM (first failure stops the batch) |
| Copy / fill / compare remote ranges | `copy_remote`, `fill_remote`, `compare_remote` (aliases `mem_*`) | RPM + WPM in **chunks** (see below) |
| Walk regions | `enumerate_regions`, `enumerate_all_regions` | `VirtualQuery(Ex)` walk |

### Enumeration filters (`region_filter`)

- `committed_only` — `MEM_COMMIT` only  
- `committed_or_reserved` — `MEM_COMMIT` or `MEM_RESERVE`  
- `all_states` — includes `MEM_FREE` (full walk)

## Errors, limits, and design

| Topic | Behavior |
|-------|----------|
| **Last error** | After a failure, `last_win32_error()` reflects `GetLastError()` or an explicit code (e.g. `ERROR_MOD_NOT_FOUND`). `clear_last_win32_error()` resets it. |
| **Per-operation cap** | `max_transfer_bytes()` = **1 GiB** for `read` / `write` / copy / fill / compare (invalid sizes fail with `ERROR_INVALID_PARAMETER` where applicable). |
| **Large ops** | `copy_remote`, `fill_remote`, and `compare_remote` stream in `transfer_chunk_bytes()` (**1 MiB**) chunks; temporary buffers are wiped with `SecureZeroMemory` after use. |
| **Threading** | **Not** thread-safe: one `manager` per thread or external synchronization. |
| **Rights** | `default_access()` — VM read/write/operation plus `PROCESS_QUERY_INFORMATION`. `read_query_access()` — read + query only (read-only tooling). |

## Minimal usage in your code

```cpp
#include "memory.h"

memory::manager m;
if (!m.attach(12345u, memory::manager::default_access()))
    return;

std::uint32_t x = 0;
void* addr = /* valid address in the target process */;
if (m.read_trivial(addr, x)) {
    // use x
}
m.detach();
```

For the **current process**, construct `memory::manager` without attaching, or use the default constructor and skip external `attach`.

## Limitations (important)

- **Usermode only**: not a driver; does not bypass PPL, anti-cheat, or protected processes.
- Typical **same-session** Windows rules: without extra privilege, many targets simply **deny** `OpenProcess` or WPM.
- This is **not** a substitute for a debugger or for ASLR / integrity reasoning; it is a thin, direct layer on documented Win32.

## License

Set your own repository license (this project does not impose one).

---

*Goal: a small, predictable API that stays easy to audit on top of documented Win32 calls.*
