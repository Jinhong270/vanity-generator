#pragma once

#include <string>

#include "hash.h"
#include "sha1_search.h"

struct Pattern {
    Sha1Target target;
    int fixed_digits;
    std::string display;
};

bool parse_pattern(const std::string& text, Pattern& out, std::string& error);
bool pattern_matches(const Pattern& pattern, const Sha1Digest& fingerprint);
