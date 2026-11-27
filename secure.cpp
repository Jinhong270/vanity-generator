#include "secure.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>
#else
#error "unsupported platform"
#endif

namespace {

[[noreturn]] void fatal_random_failure()
{
    std::fputs("fatal: the operating system random number generator failed\n", stderr);
    std::abort();
}

}

void secure_wipe(void* data, size_t size)
{
    volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
    while (size-- > 0) {
        *p++ = 0;
    }
}

void secure_random(uint8_t* data, size_t size)
{
#if defined(_WIN32)
    size_t done = 0;
    while (done < size) {
        const ULONG chunk = static_cast<ULONG>(std::min<size_t>(size - done, 1u << 20));
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, data + done, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            fatal_random_failure();
        }
        done += chunk;
    }
#else
    size_t done = 0;
    while (done < size) {
        const ssize_t n = getrandom(data + done, size - done, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fatal_random_failure();
        }
        done += static_cast<size_t>(n);
    }
#endif
}

bool secure_random_self_check()
{
    uint8_t first[32];
    uint8_t second[32];
    secure_random(first, sizeof(first));
    secure_random(second, sizeof(second));
    bool all_zero = true;
    bool identical = true;
    for (size_t i = 0; i < sizeof(first); ++i) {
        all_zero = all_zero && first[i] == 0;
        identical = identical && first[i] == second[i];
    }
    secure_wipe(first, sizeof(first));
    secure_wipe(second, sizeof(second));
    return !all_zero && !identical;
}

#if defined(_WIN32)

bool append_private_file(const std::string& path_utf8, const std::string& content, std::string& error)
{
    const int wide_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path_utf8.c_str(), -1, nullptr, 0);
    if (wide_size <= 0) {
        error = "the output path is not valid UTF-8";
        return false;
    }
    std::wstring wide(static_cast<size_t>(wide_size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path_utf8.c_str(), -1, &wide[0], wide_size);
    HANDLE file = CreateFileW(wide.c_str(), FILE_APPEND_DATA, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "cannot open the output file for writing";
        return false;
    }
    size_t total = 0;
    while (total < content.size()) {
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(content.size() - total, 1u << 20));
        if (!WriteFile(file, content.data() + total, chunk, &written, nullptr)) {
            CloseHandle(file);
            error = "cannot write to the output file";
            return false;
        }
        total += written;
    }
    const BOOL flushed = FlushFileBuffers(file);
    CloseHandle(file);
    if (!flushed) {
        error = "cannot flush the output file";
        return false;
    }
    return true;
}

#else

bool append_private_file(const std::string& path_utf8, const std::string& content, std::string& error)
{
    const int fd = open(path_utf8.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        error = "cannot open the output file for writing";
        return false;
    }
    size_t total = 0;
    while (total < content.size()) {
        const ssize_t n = write(fd, content.data() + total, content.size() - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            error = "cannot write to the output file";
            return false;
        }
        total += static_cast<size_t>(n);
    }
    const int closed = close(fd);
    if (closed != 0) {
        error = "cannot close the output file";
        return false;
    }
    return true;
}

#endif
