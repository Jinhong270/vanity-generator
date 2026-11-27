#include "pattern.h"

#include <cctype>

namespace {

int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return c - 'A' + 10;
}

}

bool parse_pattern(const std::string& text, Pattern& out, std::string& error)
{
    std::string s;
    for (char ch : text) {
        if (ch == ' ' || ch == ':') {
            continue;
        }
        s.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
    }
    if (s.empty()) {
        error = "the pattern is empty";
        return false;
    }
    size_t runs = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        const char ch = s[i];
        if (ch == '*') {
            if (i == 0 || s[i - 1] != '*') {
                ++runs;
            }
        } else if (!std::isxdigit(static_cast<unsigned char>(ch))) {
            error = "the pattern may only contain hexadecimal digits and '*'";
            return false;
        }
    }

    std::string expanded;
    if (runs == 1) {
        const size_t first = s.find('*');
        size_t end = first;
        while (end < s.size() && s[end] == '*') {
            ++end;
        }
        const std::string head = s.substr(0, first);
        const std::string tail = s.substr(end);
        if (head.size() + tail.size() > 40) {
            error = "the pattern has more than 40 fixed hexadecimal digits";
            return false;
        }
        expanded = head + std::string(40 - head.size() - tail.size(), '*') + tail;
    } else if (s.size() == 40) {
        expanded = s;
    } else if (runs == 0) {
        error = "a pattern without '*' must be exactly 40 digits; use 'ABCD*' for a prefix or '*ABCD' for a suffix";
        return false;
    } else {
        error = "a pattern with several '*' groups must be exactly 40 characters long";
        return false;
    }

    out.target = Sha1Target{};
    out.fixed_digits = 0;
    for (int i = 0; i < 40; ++i) {
        if (expanded[i] == '*') {
            continue;
        }
        const int word = i / 8;
        const int shift = 28 - 4 * (i % 8);
        out.target.value[word] |= static_cast<uint32_t>(hex_value(expanded[i])) << shift;
        out.target.mask[word] |= 0xFu << shift;
        ++out.fixed_digits;
    }
    if (out.fixed_digits == 0) {
        error = "the pattern must contain at least one hexadecimal digit";
        return false;
    }
    out.display = expanded;
    return true;
}

bool pattern_matches(const Pattern& pattern, const Sha1Digest& fingerprint)
{
    uint32_t words[5];
    for (int i = 0; i < 5; ++i) {
        words[i] = (uint32_t(fingerprint[4 * i]) << 24) | (uint32_t(fingerprint[4 * i + 1]) << 16) |
                   (uint32_t(fingerprint[4 * i + 2]) << 8) | uint32_t(fingerprint[4 * i + 3]);
    }
    return sha1_target_hit(words, pattern.target);
}
