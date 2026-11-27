#pragma once

#include <cstdint>
#include <string>

#include "ed25519.h"
#include "hash.h"

Sha1Digest openpgp_fingerprint(const Ed25519Public& pub, uint32_t created);
std::string openpgp_armored_secret_key(const Ed25519Seed& seed, const Ed25519Public& pub, uint32_t created, const std::string& user_id);
