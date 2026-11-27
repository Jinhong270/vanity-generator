#include "cli.h"

#include <cstdio>
#include <ctime>
#include <ostream>

namespace {

bool parse_uint(const std::string& s, uint64_t& out)
{
    if (s.empty() || s.size() > 18) {
        return false;
    }
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    out = v;
    return true;
}

bool read_digits(const std::string& s, size_t& pos, size_t width, int& value)
{
    if (pos + width > s.size()) {
        return false;
    }
    int v = 0;
    for (size_t i = 0; i < width; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') {
            return false;
        }
        v = v * 10 + (c - '0');
    }
    pos += width;
    value = v;
    return true;
}

bool expect_char(const std::string& s, size_t& pos, char c)
{
    if (pos < s.size() && s[pos] == c) {
        ++pos;
        return true;
    }
    return false;
}

bool is_leap_year(int y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

int days_in_month(int y, int m)
{
    static const int kDays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return (m == 2 && is_leap_year(y)) ? 29 : kDays[m - 1];
}

int64_t days_from_civil(int64_t y, int m, int d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const int64_t yoe = y - era * 400;
    const int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

void civil_from_days(int64_t z, int64_t& y, int& m, int& d)
{
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    d = static_cast<int>(doy - (153 * mp + 2) / 5 + 1);
    m = static_cast<int>(mp < 10 ? mp + 3 : mp - 9);
    y = yoe + era * 400 + (m <= 2 ? 1 : 0);
}

}

bool parse_time(const std::string& text, uint32_t& out)
{
    if (text == "now") {
        out = static_cast<uint32_t>(std::time(nullptr));
        return true;
    }
    uint64_t seconds = 0;
    if (parse_uint(text, seconds)) {
        if (seconds > 0xFFFFFFFFull) {
            return false;
        }
        out = static_cast<uint32_t>(seconds);
        return true;
    }
    size_t pos = 0;
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!read_digits(text, pos, 4, year) || !expect_char(text, pos, '-') || !read_digits(text, pos, 2, month) ||
        !expect_char(text, pos, '-') || !read_digits(text, pos, 2, day)) {
        return false;
    }
    if (pos < text.size()) {
        if (!(expect_char(text, pos, 'T') || expect_char(text, pos, ' '))) {
            return false;
        }
        if (!read_digits(text, pos, 2, hour) || !expect_char(text, pos, ':') || !read_digits(text, pos, 2, minute) ||
            !expect_char(text, pos, ':') || !read_digits(text, pos, 2, second)) {
            return false;
        }
        expect_char(text, pos, 'Z');
        if (pos != text.size()) {
            return false;
        }
    }
    if (month < 1 || month > 12 || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 59) {
        return false;
    }
    const int64_t t = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second;
    if (t < 0 || t > 0xFFFFFFFFll) {
        return false;
    }
    out = static_cast<uint32_t>(t);
    return true;
}

std::string format_time(uint32_t timestamp)
{
    int64_t year = 0;
    int month = 0, day = 0;
    civil_from_days(static_cast<int64_t>(timestamp / 86400u), year, month, day);
    const uint32_t rest = timestamp % 86400u;
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%04lld-%02d-%02d %02u:%02u:%02u UTC", static_cast<long long>(year), month, day,
                  rest / 3600u, (rest % 3600u) / 60u, rest % 60u);
    return buffer;
}

std::string format_duration(double seconds)
{
    char buffer[64];
    if (seconds < 60.0) {
        std::snprintf(buffer, sizeof(buffer), "%.1f s", seconds);
    } else if (seconds < 3600.0) {
        std::snprintf(buffer, sizeof(buffer), "%.1f min", seconds / 60.0);
    } else if (seconds < 86400.0) {
        std::snprintf(buffer, sizeof(buffer), "%.1f h", seconds / 3600.0);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%.1f d", seconds / 86400.0);
    }
    return buffer;
}

std::string to_hex(const uint8_t* data, size_t size)
{
    static const char kDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 15]);
    }
    return out;
}

bool parse_options(const std::vector<std::string>& args, Options& options, std::string& error)
{
    bool to_set = false;
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string& arg = args[i];
        auto take = [&](std::string& target) -> bool {
            if (i + 1 >= args.size()) {
                error = "missing value for " + arg;
                return false;
            }
            target = args[++i];
            return true;
        };
        std::string text;
        uint64_t number = 0;
        if (arg == "--help" || arg == "-h") {
            options.help = true;
        } else if (arg == "--pattern") {
            if (!take(options.pattern)) {
                return false;
            }
        } else if (arg == "--prefix") {
            if (!take(options.prefix)) {
                return false;
            }
        } else if (arg == "--suffix") {
            if (!take(options.suffix)) {
                return false;
            }
        } else if (arg == "--uid") {
            if (!take(options.user_id)) {
                return false;
            }
        } else if (arg == "--output") {
            if (!take(options.output)) {
                return false;
            }
        } else if (arg == "--hide-secret") {
            options.hide_secret = true;
        } else if (arg == "--from") {
            if (!take(text)) {
                return false;
            }
            if (!parse_time(text, options.from_time)) {
                error = "invalid value for --from: " + text;
                return false;
            }
        } else if (arg == "--to") {
            if (!take(text)) {
                return false;
            }
            if (!parse_time(text, options.to_time)) {
                error = "invalid value for --to: " + text;
                return false;
            }
            to_set = true;
        } else if (arg == "--count") {
            if (!take(text)) {
                return false;
            }
            if (!parse_uint(text, number) || number == 0 || number > 1000000) {
                error = "invalid value for --count: " + text;
                return false;
            }
            options.count = static_cast<uint32_t>(number);
        } else if (arg == "--device") {
            if (!take(text)) {
                return false;
            }
            if (!parse_uint(text, number) || number > 1024) {
                error = "invalid value for --device: " + text;
                return false;
            }
            options.device = static_cast<int>(number);
        } else if (arg == "--threads") {
            if (!take(text)) {
                return false;
            }
            if (!parse_uint(text, number) || number == 0 || number > 256) {
                error = "invalid value for --threads: " + text;
                return false;
            }
            options.threads = static_cast<unsigned>(number);
        } else if (!arg.empty() && arg[0] != '-' && options.pattern.empty()) {
            options.pattern = arg;
        } else {
            error = "unknown argument: " + arg;
            return false;
        }
    }
    if (options.help) {
        return true;
    }
    if (!to_set) {
        parse_time("now", options.to_time);
    }
    if ((!options.prefix.empty() || !options.suffix.empty())) {
        if (!options.pattern.empty()) {
            error = "use either --pattern or --prefix/--suffix, not both";
            return false;
        }
        options.pattern = options.prefix + "*" + options.suffix;
    }
    if (options.pattern.empty()) {
        error = "a pattern is required";
        return false;
    }
    if (options.from_time > options.to_time) {
        error = "--from must not be later than --to";
        return false;
    }
    if (options.hide_secret && options.output.empty()) {
        error = "--hide-secret requires --output";
        return false;
    }
    if (options.user_id.empty() || options.user_id.size() > 1000) {
        error = "the user ID must be between 1 and 1000 bytes";
        return false;
    }
    return true;
}

void print_usage(std::ostream& out)
{
    out << "Usage: vanity-generator --pattern <pattern> [options]\n"
           "\n"
           "Searches for an Ed25519 OpenPGP key (GnuPG compatible, v4) whose fingerprint\n"
           "matches a pattern. The key creation time is part of the fingerprint, so the\n"
           "search sweeps creation times between --from and --to on an NVIDIA GPU.\n"
           "\n"
           "Pattern: hexadecimal digits and '*'. A single run of '*' is stretched to fill the\n"
           "40-digit fingerprint; otherwise the pattern must be exactly 40 characters.\n"
           "  DEADBEEF*        fingerprint starts with DEADBEEF\n"
           "  *CAFE1234        fingerprint ends with CAFE1234 (so does the key ID)\n"
           "  8888*6666        fixed start and fixed end\n"
           "\n"
           "Options:\n"
           "  --pattern <text>   fingerprint pattern (may also be given as the first argument)\n"
           "  --prefix <hex>     leading digits, same as --pattern <hex>*<suffix>\n"
           "  --suffix <hex>     trailing digits\n"
           "  --uid <text>       user ID, default \"Vanity Key <vanity@localhost>\"\n"
           "  --from <time>      earliest creation time, default 2015-01-01\n"
           "  --to <time>        latest creation time, default now\n"
           "                     time: unix seconds, YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS (UTC)\n"
           "  --count <n>        number of matching keys to find, default 1\n"
           "  --device <n>       CUDA device index, default 0\n"
           "  --threads <n>      CPU threads for key generation, default all\n"
           "  --output <file>    append the armored private keys to this file\n"
           "  --hide-secret      do not print private keys to the console (needs --output)\n"
           "  --help             show this text\n";
}
