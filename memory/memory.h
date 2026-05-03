#pragma once

/*
 * Win32 virtual memory: same process uses memcpy/VirtualAlloc; another process uses RPM/WPM and *Ex APIs.
 */

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

namespace memory {

enum class region_filter : std::uint32_t {
    committed_only = 0,
    committed_or_reserved = 1,
    all_states = 2,
};

struct region_info {
    void* base_address{};
    std::size_t region_size{};
    DWORD state{};
    DWORD type{};
    DWORD protect{};
    DWORD allocate_protect{};
};

enum class compare_result : std::int32_t {
    error = -1,
    not_equal = 0,
    equal = 1,
};

struct batch_read_entry {
    void* address{};
    std::size_t size{};
    std::vector<std::byte> bytes;
    bool success{};

bool ok() const noexcept { return success && bytes.size() == size; }
};

struct batch_write_entry {
    void* address{};
    bool success{};
};

class manager final {
public:
    manager() noexcept;
    explicit manager(DWORD process_id, DWORD desired_access = default_access());
    ~manager();

    manager(const manager&) = delete;
    manager& operator=(const manager&) = delete;

    manager(manager&& other) noexcept;
    manager& operator=(manager&& other) noexcept;

bool attach(DWORD process_id, DWORD desired_access = default_access());
    void detach() noexcept;

bool is_attached() const noexcept { return process_ != nullptr; }
DWORD process_id() const noexcept { return process_id_; }
HANDLE native_handle() const noexcept { return process_; }

DWORD last_win32_error() const noexcept { return last_win32_; }
    void clear_last_win32_error() const noexcept { last_win32_ = ERROR_SUCCESS; }

static constexpr std::size_t max_transfer_bytes() noexcept { return 1ull << 30; }
static constexpr std::size_t transfer_chunk_bytes() noexcept { return 1ull << 20; }

bool read(void* remote_address, void* buffer, std::size_t size) const;
bool write(void* remote_address, const void* buffer, std::size_t size) const;

std::size_t read_partial(void* remote_address, void* buffer, std::size_t size) const noexcept;
std::size_t write_partial(void* remote_address, const void* buffer, std::size_t size) const noexcept;

void* allocate(std::size_t size, DWORD protection = PAGE_READWRITE) const;
bool release(void* remote_address) const noexcept;

bool protect(void* remote_address, std::size_t size, DWORD new_protection,
                               DWORD* old_protection = nullptr) const noexcept;

bool query(void* remote_address, MEMORY_BASIC_INFORMATION& mbi_out) const noexcept;
bool query_mbi(void* remote_address, MEMORY_BASIC_INFORMATION& mbi_out) const noexcept {
        return query(remote_address, mbi_out);
    }

std::vector<region_info> enumerate_regions(region_filter filter = region_filter::committed_only) const;
std::vector<region_info> enumerate_all_regions() const {
        return enumerate_regions(region_filter::all_states);
    }

void* module_base_utf8(std::string_view module_name_utf8) const;
void* get_module_base(std::string_view module_name_utf8) const {
        return module_base_utf8(module_name_utf8);
    }
void* main_module_base() const;

std::vector<batch_read_entry> batch_read(const std::vector<std::pair<void*, std::size_t>>& ops) const;
std::vector<batch_write_entry> batch_write(
        const std::vector<std::tuple<void*, const void*, std::size_t>>& ops) const;

bool copy_remote(void* dest_remote, void* src_remote, std::size_t size) const;
bool fill_remote(void* remote_address, std::size_t size, std::byte value) const;
compare_result compare_remote(void* a_remote, void* b_remote, std::size_t size) const;

bool mem_copy(void* dest_remote, void* src_remote, std::size_t size) const {
        return copy_remote(dest_remote, src_remote, size);
    }
bool mem_fill(void* remote_address, std::size_t size, std::byte value) const {
        return fill_remote(remote_address, size, value);
    }
compare_result mem_compare(void* a_remote, void* b_remote, std::size_t size) const {
        return compare_remote(a_remote, b_remote, size);
    }

    template<typename T>
bool read_trivial(void* remote_address, T& value_out) const {
        static_assert(std::is_trivially_copyable_v<T>);
        return read(remote_address, &value_out, sizeof(T));
    }

    template<typename T>
bool write_trivial(void* remote_address, const T& value) const {
        static_assert(std::is_trivially_copyable_v<T>);
        return write(remote_address, &value, sizeof(T));
    }

static constexpr DWORD default_access() noexcept {
        return PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    }

static constexpr DWORD read_query_access() noexcept {
        return PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    }

private:
    HANDLE process_{};
    DWORD process_id_{};
    bool external_{};
    mutable DWORD last_win32_{ERROR_SUCCESS};

bool validate_transfer(std::size_t size) const noexcept;
    void note_error(DWORD code) const noexcept;
    void note_last_error() const noexcept;
    void clear_error() const noexcept;

bool read_impl(void* remote_address, void* buffer, std::size_t size, std::size_t* transferred) const noexcept;
bool write_impl(void* remote_address, const void* buffer, std::size_t size,
                                  std::size_t* transferred) const noexcept;
};

}
