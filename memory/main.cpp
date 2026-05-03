#include "memory.h"

#include <TlHelp32.h>

#include <cinttypes>
#include <cstdio>
#include <conio.h>
#include <exception>
#include <vector>

namespace {

DWORD find_process_id(const wchar_t* exe_name) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool is_remote(const memory::manager& m) noexcept {
    return m.process_id() != GetCurrentProcessId();
}

void fail(const memory::manager& m, const char* what) {
    const DWORD e = m.last_win32_error();
    if (e != 0)
        printf("[-] %s  win32=%lu (0x%lX)\n", what, static_cast<unsigned long>(e), static_cast<unsigned long>(e));
    else
        printf("[-] %s\n", what);
}

void hex4(const unsigned char* b, char* out, std::size_t outsz) {
    if (outsz < 3) {
        out[0] = 0;
        return;
    }
    std::size_t o = 0;
    for (int i = 0; i < 4 && o + 3 < outsz; ++i)
        o += static_cast<std::size_t>(snprintf(out + o, outsz - o, "%02X", b[i]));
}

void run_checklist(memory::manager& m) {
    const bool rpm = is_remote(m);
    const char* wtag = rpm ? "WriteProcessMemory" : "memcpy (local write)";
    const char* rtag = rpm ? "ReadProcessMemory" : "memcpy (local read)";

    void* p = m.allocate(4096);
    if (!p) {
        fail(m, rpm ? "VirtualAllocEx" : "VirtualAlloc");
        return;
    }
    printf("[+] %s -> %p  (size=4096, PAGE_READWRITE)\n", rpm ? "VirtualAllocEx" : "VirtualAlloc", p);

    const unsigned int magic = 0xDEADBEEF;
    unsigned int rb = 0;
    if (m.write(p, &magic, sizeof(magic)) && m.read(p, &rb, sizeof(rb)) && rb == magic) {
        printf("[+] %s  remote=%p  size=%zu  dword=0x%08X\n", wtag, p, sizeof(magic), magic);
        printf("[+] %s  remote=%p  size=%zu  dword=0x%08X  (match)\n", rtag, p, sizeof(rb), rb);
    } else {
        fail(m, "Read/Write");
    }

    DWORD oldp = 0;
    if (m.protect(p, 4096, PAGE_EXECUTE_READWRITE, &oldp)) {
        printf("[+] %s  addr=%p  size=4096  new=PAGE_EXECUTE_READWRITE  old_protect=0x%08lX\n",
               rpm ? "VirtualProtectEx" : "VirtualProtect", p, static_cast<unsigned long>(oldp));
    } else {
        fail(m, rpm ? "VirtualProtectEx" : "VirtualProtect");
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (m.query_mbi(p, mbi)) {
        printf("[+] %s  BaseAddress=%p  RegionSize=%llu  State=0x%lx  Type=0x%lx  Protect=0x%lx  AllocationBase=%p\n",
               rpm ? "VirtualQueryEx" : "VirtualQuery", mbi.BaseAddress,
               static_cast<unsigned long long>(mbi.RegionSize), static_cast<unsigned long>(mbi.State),
               static_cast<unsigned long>(mbi.Type), static_cast<unsigned long>(mbi.Protect), mbi.AllocationBase);
    } else {
        fail(m, rpm ? "VirtualQueryEx" : "VirtualQuery");
    }

    void* k32 = m.get_module_base("kernel32.dll");
    void* exe = m.main_module_base();
    if (k32 && exe) {
        printf("[+] CreateToolhelp32Snapshot+Module32  kernel32.dll base=%p  main image base=%p\n", k32, exe);
        unsigned char mz[2]{};
        if (m.read(exe, mz, 2) && mz[0] == 'M' && mz[1] == 'Z')
            printf("[+] read first 2 bytes at main base -> %02X %02X ('MZ')\n", mz[0], mz[1]);
        else
            printf("[+] main base read -> %02X %02X (not MZ?)\n", mz[0], mz[1]);
    } else {
        fail(m, "GetModuleBase (Toolhelp)");
    }

    std::vector<std::pair<void*, std::size_t>> br_ops{{p, 4}, {static_cast<std::byte*>(p) + 4, 4}};
    const auto br = m.batch_read(br_ops);
    if (br.size() >= 2 && br[0].ok() && br[1].ok()) {
        char h0[16]{}, h1[16]{};
        hex4(reinterpret_cast<const unsigned char*>(br[0].bytes.data()), h0, sizeof h0);
        hex4(reinterpret_cast<const unsigned char*>(br[1].bytes.data()), h1, sizeof h1);
        printf("[+] BatchRead  [%p,4] -> %s  [%p,4] -> %s\n", br[0].address, h0, br[1].address, h1);
    } else {
        fail(m, "BatchRead");
    }

    unsigned int w1 = 0x11111111, w2 = 0x22222222;
    void* a1 = static_cast<std::byte*>(p) + 0x100;
    void* a2 = static_cast<std::byte*>(p) + 0x104;
    std::vector<std::tuple<void*, const void*, std::size_t>> bw_ops{{a1, &w1, sizeof(w1)}, {a2, &w2, sizeof(w2)}};
    const auto bw = m.batch_write(bw_ops);
    if (bw.size() >= 2 && bw[0].success && bw[1].success) {
        unsigned int v1 = 0, v2 = 0;
        if (m.read(a1, &v1, sizeof(v1)) && m.read(a2, &v2, sizeof(v2)))
            printf("[+] BatchWrite  %p=0x%08X  %p=0x%08X  (verified read back)\n", a1, v1, a2, v2);
        else
            printf("[+] BatchWrite  %p %p  (write ok, verify read failed)\n", a1, a2);
    } else {
        fail(m, "BatchWrite");
    }

    void* p2 = m.allocate(4096);
    if (!p2) {
        fail(m, rpm ? "VirtualAllocEx (2nd block)" : "VirtualAlloc (2nd block)");
    } else {
        printf("[+] %s -> %p  (for MemCopy/MemFill/MemCompare)\n", rpm ? "VirtualAllocEx" : "VirtualAlloc", p2);
        if (m.write(p, &magic, 4) && m.mem_copy(p2, p, 4))
            printf("[+] MemCopy  dst=%p  src=%p  bytes=4  (copied first dword from %p)\n", p2, p, p);
        else
            fail(m, "MemCopy");

        if (m.mem_fill(p2, 16, std::byte{0x5A})) {
            unsigned char buf[16]{};
            if (m.read(p2, buf, sizeof(buf))) {
                char hx[64]{};
                hex4(buf, hx, sizeof hx);
                printf("[+] MemFill  addr=%p  len=16  byte=0x5A  first4=%s...\n", p2, hx);
            } else
                printf("[+] MemFill  addr=%p  len=16  byte=0x5A\n", p2);
        } else
            fail(m, "MemFill");

        if (m.mem_compare(p2, p2, 8) == memory::compare_result::equal)
            printf("[+] MemCompare  range [%p,8] vs same  (equal)\n", p2);
        else
            fail(m, "MemCompare");

        if (m.release(p2))
            printf("[+] %s  %p\n", rpm ? "VirtualFreeEx" : "VirtualFree", p2);
        else
            fail(m, rpm ? "VirtualFreeEx" : "VirtualFree");
    }

    const auto all = m.enumerate_all_regions();
    if (!all.empty()) {
        printf("[+] EnumerateRegions (%s walk, all states)  count=%zu\n", rpm ? "VirtualQueryEx" : "VirtualQuery",
               all.size());
        const std::size_t nshow = all.size() < 5 ? all.size() : 5;
        for (std::size_t i = 0; i < nshow; ++i)
            printf("    [%zu] base=%p  size=%llu  state=0x%lx  protect=0x%lx\n", i, all[i].base_address,
                   static_cast<unsigned long long>(all[i].region_size), static_cast<unsigned long>(all[i].state),
                   static_cast<unsigned long>(all[i].protect));
        if (all.size() > nshow)
            printf("    ... %zu more regions\n", all.size() - nshow);
    } else {
        fail(m, "EnumerateRegions");
    }

    if (m.release(p))
        printf("[+] %s  %p\n", rpm ? "VirtualFreeEx" : "VirtualFree", p);
    else
        fail(m, rpm ? "VirtualFreeEx" : "VirtualFree");
}

}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);

    try {
        const DWORD pid = find_process_id(L"notepad.exe");
        memory::manager m;

        if (pid != 0 && m.attach(pid, memory::manager::default_access()) && m.process_id() == pid) {
            printf("[+] target : notepad  (pid=%lu)\n\n", static_cast<unsigned long>(pid));
            run_checklist(m);
            m.detach();
        } else {
            printf("[+] target : local  (pid=%lu)\n\n", static_cast<unsigned long>(GetCurrentProcessId()));
            memory::manager local;
            run_checklist(local);
        }
    } catch (const std::exception& ex) {
        fprintf(stderr, "[-] exception: %s\n", ex.what());
    } catch (...) {
        fputs("[-] exception\n", stderr);
    }

    fflush(stdout);
    fflush(stderr);
    fputs("\nPress any key . . .\n", stdout);
    fflush(stdout);
    (void)_getch();
    return 0;
}
