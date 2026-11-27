#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sha1_search.h"

constexpr uint32_t kGpuMaxKeys = 512;

struct GpuHit {
    uint32_t key;
    uint32_t timestamp;
};

struct GpuInfo {
    std::string name;
    int major = 0;
    int minor = 0;
    int multiprocessors = 0;
};

bool gpu_init(int device, GpuInfo& info, std::string& error);

bool gpu_run(const std::vector<uint32_t>& key_words, uint32_t key_count, uint32_t first_timestamp, uint64_t timestamp_count,
             const Sha1Target& target, std::vector<GpuHit>& hits, uint32_t& total_hits, std::string& error);

void gpu_shutdown();
