#include "gpu.h"

#include <cuda_runtime.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "sha1_search.h"

namespace {

constexpr int kBlockSize = 256;
constexpr uint32_t kTimestampsPerThread = 32;
constexpr uint32_t kMaxHits = 256;

struct DeviceHits {
    uint32_t count;
    uint32_t reserved;
    GpuHit hits[kMaxHits];
};

uint32_t* g_device_keys = nullptr;
DeviceHits* g_device_hits = nullptr;

std::string describe(const char* what, cudaError_t status)
{
    std::string text = what;
    text += ": ";
    text += cudaGetErrorString(status);
    return text;
}

__global__ void __launch_bounds__(kBlockSize)
search_kernel(const uint32_t* __restrict__ keys, uint32_t first_timestamp, uint64_t timestamp_count, Sha1Target target,
              DeviceHits* out)
{
    const uint64_t begin = (static_cast<uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x) * kTimestampsPerThread;
    if (begin >= timestamp_count) {
        return;
    }
    uint64_t end = begin + kTimestampsPerThread;
    if (end > timestamp_count) {
        end = timestamp_count;
    }
    const uint32_t steps = static_cast<uint32_t>(end - begin);
    const uint32_t key_index = blockIdx.y;

    uint32_t words[kKeyWordCount];
    for (int i = 0; i < kKeyWordCount; ++i) {
        words[i] = keys[static_cast<size_t>(key_index) * kKeyWordCount + i];
    }

    const uint32_t first = first_timestamp + static_cast<uint32_t>(begin);
    for (uint32_t step = 0; step < steps; ++step) {
        const uint32_t timestamp = first + step;
        uint32_t digest[5];
        sha1_key_digest(words, timestamp, digest);
        if (sha1_target_hit(digest, target)) {
            const uint32_t slot = atomicAdd(&out->count, 1u);
            if (slot < kMaxHits) {
                out->hits[slot].key = key_index;
                out->hits[slot].timestamp = timestamp;
            }
        }
    }
}

}

bool gpu_init(int device, GpuInfo& info, std::string& error)
{
    cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
    cudaGetLastError();

    int device_count = 0;
    cudaError_t status = cudaGetDeviceCount(&device_count);
    if (status != cudaSuccess) {
        error = describe("cannot query CUDA devices", status);
        return false;
    }
    if (device_count == 0) {
        error = "no CUDA capable device was found";
        return false;
    }
    if (device < 0 || device >= device_count) {
        error = "device index out of range, " + std::to_string(device_count) + " device(s) available";
        return false;
    }
    status = cudaSetDevice(device);
    if (status != cudaSuccess) {
        error = describe("cannot select the CUDA device", status);
        return false;
    }

    cudaDeviceProp properties;
    status = cudaGetDeviceProperties(&properties, device);
    if (status != cudaSuccess) {
        error = describe("cannot read the CUDA device properties", status);
        return false;
    }
    info.name = properties.name;
    info.major = properties.major;
    info.minor = properties.minor;
    int multiprocessors = 0;
    cudaDeviceGetAttribute(&multiprocessors, cudaDevAttrMultiProcessorCount, device);
    info.multiprocessors = multiprocessors;

    status = cudaMalloc(reinterpret_cast<void**>(&g_device_keys), static_cast<size_t>(kGpuMaxKeys) * kKeyWordCount * sizeof(uint32_t));
    if (status != cudaSuccess) {
        error = describe("cannot allocate device memory", status);
        return false;
    }
    status = cudaMalloc(reinterpret_cast<void**>(&g_device_hits), sizeof(DeviceHits));
    if (status != cudaSuccess) {
        error = describe("cannot allocate device memory", status);
        gpu_shutdown();
        return false;
    }
    return true;
}

bool gpu_run(const std::vector<uint32_t>& key_words, uint32_t key_count, uint32_t first_timestamp, uint64_t timestamp_count,
             const Sha1Target& target, std::vector<GpuHit>& hits, uint32_t& total_hits, std::string& error)
{
    if (key_count == 0 || key_count > kGpuMaxKeys || key_words.size() < static_cast<size_t>(key_count) * kKeyWordCount) {
        error = "invalid key batch";
        return false;
    }
    cudaError_t status = cudaMemcpy(g_device_keys, key_words.data(), static_cast<size_t>(key_count) * kKeyWordCount * sizeof(uint32_t),
                                    cudaMemcpyHostToDevice);
    if (status != cudaSuccess) {
        error = describe("cannot upload public keys", status);
        return false;
    }
    status = cudaMemset(g_device_hits, 0, sizeof(uint32_t));
    if (status != cudaSuccess) {
        error = describe("cannot reset the hit counter", status);
        return false;
    }

    const uint64_t per_block = static_cast<uint64_t>(kBlockSize) * kTimestampsPerThread;
    const dim3 block(kBlockSize);
    const dim3 grid(static_cast<unsigned int>((timestamp_count + per_block - 1) / per_block), key_count);
    search_kernel<<<grid, block>>>(g_device_keys, first_timestamp, timestamp_count, target, g_device_hits);

    status = cudaGetLastError();
    if (status != cudaSuccess) {
        error = describe("kernel launch failed", status);
        return false;
    }
    status = cudaDeviceSynchronize();
    if (status != cudaSuccess) {
        error = describe("kernel execution failed", status);
        return false;
    }

    DeviceHits host_hits;
    status = cudaMemcpy(&host_hits, g_device_hits, sizeof(host_hits), cudaMemcpyDeviceToHost);
    if (status != cudaSuccess) {
        error = describe("cannot read the search results", status);
        return false;
    }
    total_hits = host_hits.count;
    const uint32_t stored = host_hits.count < kMaxHits ? host_hits.count : kMaxHits;
    hits.assign(host_hits.hits, host_hits.hits + stored);
    return true;
}

void gpu_shutdown()
{
    if (g_device_keys != nullptr) {
        cudaFree(g_device_keys);
        g_device_keys = nullptr;
    }
    if (g_device_hits != nullptr) {
        cudaFree(g_device_hits);
        g_device_hits = nullptr;
    }
}
