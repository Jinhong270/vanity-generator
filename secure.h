#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

void secure_random(uint8_t* data, size_t size);
bool secure_random_self_check();
void secure_wipe(void* data, size_t size);
bool append_private_file(const std::string& path_utf8, const std::string& content, std::string& error);
