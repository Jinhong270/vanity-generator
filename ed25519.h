#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

using Ed25519Seed = std::array<uint8_t, 32>;
using Ed25519Public = std::array<uint8_t, 32>;
using Ed25519Signature = std::array<uint8_t, 64>;

void ed25519_warm_up();
Ed25519Public ed25519_derive_public(const Ed25519Seed& seed);
Ed25519Signature ed25519_sign(const Ed25519Seed& seed, const Ed25519Public& pub, const uint8_t* message, size_t size);
