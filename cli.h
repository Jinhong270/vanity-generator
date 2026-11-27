#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

struct Options {
    std::string pattern;
    std::string prefix;
    std::string suffix;
    std::string user_id = "Vanity Key <vanity@localhost>";
    uint32_t from_time = 1420070400u;
    uint32_t to_time = 0;
    uint32_t count = 1;
    int device = 0;
    unsigned threads = 0;
    std::string output;
    bool hide_secret = false;
    bool help = false;
};

bool parse_options(const std::vector<std::string>& args, Options& options, std::string& error);
void print_usage(std::ostream& out);
bool parse_time(const std::string& text, uint32_t& out);
std::string format_time(uint32_t timestamp);
std::string format_duration(double seconds);
std::string to_hex(const uint8_t* data, size_t size);
