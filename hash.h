#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

using Sha1Digest = std::array<uint8_t, 20>;
using Sha256Digest = std::array<uint8_t, 32>;
using Sha512Digest = std::array<uint8_t, 64>;

Sha1Digest sha1(const uint8_t* data, size_t size);
Sha256Digest sha256(const uint8_t* data, size_t size);
Sha512Digest sha512(const uint8_t* data, size_t size);
