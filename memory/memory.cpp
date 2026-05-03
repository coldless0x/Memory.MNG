#include <algorithm>
#include <cstring>
#include <string>

#include "memory.h"

#include <TlHelp32.h>

namespace memory {

namespace {

DWORD module_snapshot_flags() noexcept {
#if defined(_WIN64)
    return TH32CS_SNAPMODULE;
#else
    return TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
#endif
}

bool utf8_to_wide(std::string_view utf8, std::wstring& wide_out) {
    wide_out.clear();
    if (utf8.empty())
        return true;
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (n <= 0)
        return false;
    wide_out.resize(static_cast<std::size_t>(n));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), wide_out.data(), n) == n;
}

bool region_matches_filter(const MEMORY_BASIC_INFORMATION& mbi, region_filter f) noexcept {
    switch (f) {
    case region_filter::committed_only:
        return mbi.State == MEM_COMMIT;
    case region_filter::committed_or_reserved:
        return mbi.State == MEM_COMMIT || mbi.State == MEM_RESERVE;
    case region_filter::all_states:
        return true;
    default:
        return false;
    }
}

void secure_zero(void* p, std::size_t n) noexcept {
    if (p && n)
        SecureZeroMemory(p, n);
}

}

void manager::note_error(const DWORD code) const noexcept {
    last_win32_ = code;
}

void manager::note_last_error() const noexcept {
    last_win32_ = ::GetLastError();
}

void manager::clear_error() const noexcept {
    last_win32_ = ERROR_SUCCESS;
}

bool manager::validate_transfer(const std::size_t size) const noexcept {
    if (size == 0) {
        note_error(ERROR_INVALID_PARAMETER);
        return false;
    }
    if (size > max_transfer_bytes()) {
        note_error(ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}

manager::manager() noexcept : process_(GetCurrentProcess()), process_id_(GetCurrentProcessId()), external_(false) {}

manager::manager(const DWORD process_id, const DWORD desired_access) : manager() {
    (void)attach(process_id, desired_access);
}

manager::~manager() {
    if (external_ && process_ && process_ != INVALID_HANDLE_VALUE)
        CloseHandle(process_);
}

manager::manager(manager&& other) noexcept : process_(other.process_), process_id_(other.process_id_), external_(other.external_),
                                             last_win32_(other.last_win32_) {
    other.process_ = GetCurrentProcess();
    other.process_id_ = GetCurrentProcessId();
    other.external_ = false;
    other.last_win32_ = ERROR_SUCCESS;
}

manager& manager::operator=(manager&& other) noexcept {
    if (this == &other)
        return *this;
    if (external_ && process_ && process_ != INVALID_HANDLE_VALUE)
        CloseHandle(process_);
    process_ = other.process_;
    process_id_ = other.process_id_;
    external_ = other.external_;
    last_win32_ = other.last_win32_;
    other.process_ = GetCurrentProcess();
    other.process_id_ = GetCurrentProcessId();
    other.external_ = false;
    other.last_win32_ = ERROR_SUCCESS;
    return *this;
}

bool manager::attach(const DWORD process_id, const DWORD desired_access) {
    clear_error();

    if (external_ && process_ && process_ != INVALID_HANDLE_VALUE)
        CloseHandle(process_);

    process_ = GetCurrentProcess();
    process_id_ = GetCurrentProcessId();
    external_ = false;

    if (process_id == process_id_)
        return true;

    const HANDLE h = OpenProcess(desired_access, FALSE, process_id);
    if (!h || h == INVALID_HANDLE_VALUE) {
        note_last_error();
        return false;
    }

    process_ = h;
    process_id_ = process_id;
    external_ = true;
    clear_error();
    return true;
}

void manager::detach() noexcept {
    if (external_ && process_ && process_ != INVALID_HANDLE_VALUE)
        CloseHandle(process_);
    process_ = GetCurrentProcess();
    process_id_ = GetCurrentProcessId();
    external_ = false;
    last_win32_ = ERROR_SUCCESS;
}

bool manager::read_impl(void* const remote_address, void* const buffer, const std::size_t size,
                        std::size_t* const transferred) const noexcept {
    if (!process_ || !buffer || size == 0)
        return false;

    if (!external_) {
        std::memcpy(buffer, remote_address, size);
        if (transferred)
            *transferred = size;
        return true;
    }

    SIZE_T n = 0;
    if (!ReadProcessMemory(process_, remote_address, buffer, size, &n)) {
        note_last_error();
        return false;
    }
    if (transferred)
        *transferred = static_cast<std::size_t>(n);
    return n == size;
}

bool manager::write_impl(void* const remote_address, const void* const buffer, const std::size_t size,
                         std::size_t* const transferred) const noexcept {
    if (!process_ || !buffer || size == 0)
        return false;

    if (!external_) {
        std::memcpy(remote_address, buffer, size);
        if (transferred)
            *transferred = size;
        return true;
    }

    SIZE_T n = 0;
    if (!WriteProcessMemory(process_, remote_address, buffer, size, &n)) {
        note_last_error();
        return false;
    }
    if (transferred)
        *transferred = static_cast<std::size_t>(n);
    return n == size;
}

bool manager::read(void* const remote_address, void* const buffer, const std::size_t size) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return false;
    }
    if (!buffer) {
        note_error(ERROR_INVALID_PARAMETER);
        return false;
    }
    if (!validate_transfer(size))
        return false;

    std::size_t t = 0;
    if (!read_impl(remote_address, buffer, size, &t))
        return false;
    clear_error();
    return true;
}

bool manager::write(void* const remote_address, const void* const buffer, const std::size_t size) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return false;
    }
    if (!buffer) {
        note_error(ERROR_INVALID_PARAMETER);
        return false;
    }
    if (!validate_transfer(size))
        return false;

    std::size_t t = 0;
    if (!write_impl(remote_address, buffer, size, &t))
        return false;
    clear_error();
    return true;
}

std::size_t manager::read_partial(void* const remote_address, void* const buffer, const std::size_t size) const noexcept {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    if (!buffer || size == 0) {
        note_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (size > max_transfer_bytes()) {
        note_error(ERROR_BAD_LENGTH);
        return 0;
    }
    if (!external_) {
        std::memcpy(buffer, remote_address, size);
        clear_error();
        return size;
    }
    SIZE_T n = 0;
    if (!ReadProcessMemory(process_, remote_address, buffer, size, &n)) {
        note_last_error();
        return 0;
    }
    clear_error();
    return static_cast<std::size_t>(n);
}

std::size_t manager::write_partial(void* const remote_address, const void* const buffer, const std::size_t size) const noexcept {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return 0;
    }
    if (!buffer || size == 0) {
        note_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (size > max_transfer_bytes()) {
        note_error(ERROR_BAD_LENGTH);
        return 0;
    }
    if (!external_) {
        std::memcpy(remote_address, buffer, size);
        clear_error();
        return size;
    }
    SIZE_T n = 0;
    if (!WriteProcessMemory(process_, remote_address, buffer, size, &n)) {
        note_last_error();
        return 0;
    }
    clear_error();
    return static_cast<std::size_t>(n);
}

void* manager::allocate(const std::size_t size, const DWORD protection) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return nullptr;
    }
    if (size == 0 || size > max_transfer_bytes()) {
        note_error(ERROR_INVALID_PARAMETER);
        return nullptr;
    }

    void* p = nullptr;
    if (!external_)
        p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
    else
        p = VirtualAllocEx(process_, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);

    if (!p)
        note_last_error();
    else
        clear_error();
    return p;
}

bool manager::release(void* const remote_address) const noexcept {
    clear_error();
    if (!process_ || !remote_address) {
        note_error(ERROR_INVALID_PARAMETER);
        return false;
    }
    const BOOL ok = external_ ? VirtualFreeEx(process_, remote_address, 0, MEM_RELEASE) : VirtualFree(remote_address, 0, MEM_RELEASE);
    if (!ok)
        note_last_error();
    else
        clear_error();
    return ok != FALSE;
}

bool manager::protect(void* const remote_address, const std::size_t size, const DWORD new_protection,
                      DWORD* const old_protection) const noexcept {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return false;
    }
    if (!validate_transfer(size))
        return false;

    DWORD old = 0;
    void* addr = remote_address;
    SIZE_T sz = size;
    const BOOL ok =
        external_ ? VirtualProtectEx(process_, addr, sz, new_protection, &old) : VirtualProtect(addr, sz, new_protection, &old);
    if (ok && old_protection)
        *old_protection = old;
    if (!ok)
        note_last_error();
    else
        clear_error();
    return ok != FALSE;
}

bool manager::query(void* const remote_address, MEMORY_BASIC_INFORMATION& mbi_out) const noexcept {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return false;
    }
    const SIZE_T r =
        external_ ? VirtualQueryEx(process_, remote_address, &mbi_out, sizeof(mbi_out)) : VirtualQuery(remote_address, &mbi_out, sizeof(mbi_out));
    if (r != sizeof(mbi_out))
        note_last_error();
    else
        clear_error();
    return r == sizeof(mbi_out);
}

std::vector<region_info> manager::enumerate_regions(const region_filter filter) const {
    clear_error();
    std::vector<region_info> regions;
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return regions;
    }

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const auto* const max_addr = static_cast<const std::byte*>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi{};
    auto* p = static_cast<std::byte*>(nullptr);

    while (p < max_addr) {
        if (!query(p, mbi))
            break;

        if (region_matches_filter(mbi, filter)) {
            region_info ri{};
            ri.base_address = mbi.BaseAddress;
            ri.region_size = static_cast<std::size_t>(mbi.RegionSize);
            ri.state = mbi.State;
            ri.type = mbi.Type;
            ri.protect = mbi.Protect;
            ri.allocate_protect = mbi.AllocationProtect;
            regions.push_back(ri);
        }

        const std::size_t step = static_cast<std::size_t>(mbi.RegionSize);
        if (step == 0)
            break;
        p = static_cast<std::byte*>(mbi.BaseAddress) + step;
    }

    return regions;
}

void* manager::module_base_utf8(const std::string_view module_name_utf8) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return nullptr;
    }

    std::wstring module_name_wide;
    if (!utf8_to_wide(module_name_utf8, module_name_wide)) {
        note_error(ERROR_NO_UNICODE_TRANSLATION);
        return nullptr;
    }

    const HANDLE snap = CreateToolhelp32Snapshot(module_snapshot_flags(), process_id_);
    if (snap == INVALID_HANDLE_VALUE) {
        note_last_error();
        return nullptr;
    }

    void* base = nullptr;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        note_last_error();
        return nullptr;
    }
    do {
        if (_wcsicmp(me.szModule, module_name_wide.c_str()) == 0) {
            base = me.modBaseAddr;
            break;
        }
    } while (Module32NextW(snap, &me));

    CloseHandle(snap);
    if (!base)
        note_error(ERROR_MOD_NOT_FOUND);
    else
        clear_error();
    return base;
}

void* manager::main_module_base() const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return nullptr;
    }

    const HANDLE snap = CreateToolhelp32Snapshot(module_snapshot_flags(), process_id_);
    if (snap == INVALID_HANDLE_VALUE) {
        note_last_error();
        return nullptr;
    }

    void* base = nullptr;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) {
        CloseHandle(snap);
        note_last_error();
        return nullptr;
    }
    base = me.modBaseAddr;

    CloseHandle(snap);
    clear_error();
    return base;
}

std::vector<batch_read_entry> manager::batch_read(const std::vector<std::pair<void*, std::size_t>>& ops) const {
    clear_error();
    std::vector<batch_read_entry> results;
    results.reserve(ops.size());

    for (const auto& op : ops) {
        batch_read_entry e{};
        e.address = op.first;
        e.size = op.second;
        if (!process_) {
            note_error(ERROR_INVALID_HANDLE);
            e.success = false;
            results.push_back(std::move(e));
            break;
        }
        if (!validate_transfer(op.second)) {
            e.success = false;
            results.push_back(std::move(e));
            break;
        }

        e.bytes.resize(op.second);
        e.success = read(op.first, e.bytes.data(), op.second);
        if (!e.success)
            e.bytes.clear();
        results.push_back(std::move(e));
        if (!e.success)
            break;
    }

    return results;
}

std::vector<batch_write_entry> manager::batch_write(
    const std::vector<std::tuple<void*, const void*, std::size_t>>& ops) const {
    clear_error();
    std::vector<batch_write_entry> results;
    results.reserve(ops.size());

    for (const auto& op : ops) {
        batch_write_entry e{};
        e.address = std::get<0>(op);
        const void* buf = std::get<1>(op);
        const std::size_t sz = std::get<2>(op);
        if (!process_) {
            note_error(ERROR_INVALID_HANDLE);
            e.success = false;
            results.push_back(e);
            break;
        }
        if (!buf) {
            note_error(ERROR_INVALID_PARAMETER);
            e.success = false;
            results.push_back(e);
            break;
        }
        if (!validate_transfer(sz)) {
            e.success = false;
            results.push_back(e);
            break;
        }
        e.success = write(e.address, buf, sz);
        results.push_back(e);
        if (!e.success)
            break;
    }

    return results;
}

bool manager::copy_remote(void* const dest_remote, void* const src_remote, const std::size_t size) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return false;
    }
    if (!validate_transfer(size))
        return false;

    const std::size_t chunk_sz = transfer_chunk_bytes();
    std::vector<std::byte> chunk;
    chunk.resize(std::min(chunk_sz, size));

    for (std::size_t off = 0; off < size;) {
        const std::size_t n = std::min(chunk_sz, size - off);
        if (chunk.size() < n)
            chunk.resize(n);

        void* const s = static_cast<std::byte*>(src_remote) + off;
        void* const d = static_cast<std::byte*>(dest_remote) + off;

        std::size_t tr = 0;
        if (!read_impl(s, chunk.data(), n, &tr)) {
            secure_zero(chunk.data(), chunk.size());
            return false;
        }
        if (!write_impl(d, chunk.data(), n, &tr)) {
            secure_zero(chunk.data(), chunk.size());
            return false;
        }
        secure_zero(chunk.data(), n);
        off += n;
    }

    clear_error();
    return true;
}

bool manager::fill_remote(void* const remote_address, const std::size_t size, const std::byte value) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return false;
    }
    if (!validate_transfer(size))
        return false;

    const std::size_t chunk_sz = transfer_chunk_bytes();
    std::vector<std::byte> chunk(std::min(chunk_sz, size), value);

    for (std::size_t off = 0; off < size;) {
        const std::size_t n = std::min(chunk_sz, size - off);
        if (chunk.size() < n)
            chunk.assign(n, value);

        void* const d = static_cast<std::byte*>(remote_address) + off;
        std::size_t tr = 0;
        if (!write_impl(d, chunk.data(), n, &tr)) {
            secure_zero(chunk.data(), chunk.size());
            return false;
        }
        off += n;
    }

    clear_error();
    return true;
}

compare_result manager::compare_remote(void* const a_remote, void* const b_remote, const std::size_t size) const {
    clear_error();
    if (!process_) {
        note_error(ERROR_INVALID_HANDLE);
        return compare_result::error;
    }
    if (size == 0)
        return compare_result::equal;
    if (!validate_transfer(size))
        return compare_result::error;

    const std::size_t chunk_sz = transfer_chunk_bytes();
    std::vector<std::byte> a(std::min(chunk_sz, size));
    std::vector<std::byte> b(std::min(chunk_sz, size));

    for (std::size_t off = 0; off < size;) {
        const std::size_t n = std::min(chunk_sz, size - off);
        if (a.size() < n) {
            a.resize(n);
            b.resize(n);
        }

        void* const pa = static_cast<std::byte*>(a_remote) + off;
        void* const pb = static_cast<std::byte*>(b_remote) + off;

        std::size_t tra = 0;
        std::size_t trb = 0;
        if (!read_impl(pa, a.data(), n, &tra) || !read_impl(pb, b.data(), n, &trb)) {
            secure_zero(a.data(), a.size());
            secure_zero(b.data(), b.size());
            return compare_result::error;
        }
        if (std::memcmp(a.data(), b.data(), n) != 0) {
            secure_zero(a.data(), n);
            secure_zero(b.data(), n);
            clear_error();
            return compare_result::not_equal;
        }
        secure_zero(a.data(), n);
        secure_zero(b.data(), n);
        off += n;
    }

    clear_error();
    return compare_result::equal;
}

}

