#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#endif

#include "cli.h"
#include "ed25519.h"
#include "gpu.h"
#include "openpgp.h"
#include "pattern.h"
#include "secure.h"
#include "sha1_search.h"

namespace {

constexpr uint64_t kLaunchWork = 1ull << 31;
constexpr size_t kQueueCapacity = 3;

std::atomic<bool> g_stop{false};

void handle_signal(int)
{
    g_stop.store(true);
}

std::vector<std::string> collect_arguments(int argc, char** argv)
{
    std::vector<std::string> args;
#if defined(_WIN32)
    int wide_count = 0;
    LPWSTR* wide = CommandLineToArgvW(GetCommandLineW(), &wide_count);
    if (wide != nullptr) {
        for (int i = 0; i < wide_count; ++i) {
            const int size = WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, nullptr, 0, nullptr, nullptr);
            std::string utf8(size > 1 ? static_cast<size_t>(size - 1) : 0u, '\0');
            if (size > 1) {
                WideCharToMultiByte(CP_UTF8, 0, wide[i], -1, &utf8[0], size, nullptr, nullptr);
            }
            args.push_back(std::move(utf8));
        }
        LocalFree(wide);
        return args;
    }
#endif
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return args;
}

struct Batch {
    std::vector<Ed25519Seed> seeds;
    std::vector<Ed25519Public> publics;
    std::vector<uint32_t> words;
};

void wipe_batch(Batch& batch)
{
    if (!batch.seeds.empty()) {
        secure_wipe(batch.seeds.data(), batch.seeds.size() * sizeof(Ed25519Seed));
    }
}

class BatchQueue {
public:
    explicit BatchQueue(size_t capacity) : capacity_(capacity) {}

    bool push(Batch& batch)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return closed_ || items_.size() < capacity_; });
        if (closed_) {
            return false;
        }
        items_.push_back(std::move(batch));
        lock.unlock();
        not_empty_.notify_one();
        return true;
    }

    bool pop(Batch& batch)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return closed_ || !items_.empty(); });
        if (closed_) {
            return false;
        }
        batch = std::move(items_.front());
        items_.pop_front();
        lock.unlock();
        not_full_.notify_one();
        return true;
    }

    void close()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
            for (Batch& item : items_) {
                wipe_batch(item);
            }
            items_.clear();
        }
        not_full_.notify_all();
        not_empty_.notify_all();
    }

private:
    size_t capacity_;
    bool closed_ = false;
    std::deque<Batch> items_;
    std::mutex mutex_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
};

void generate_key(Ed25519Seed& seed, Ed25519Public& pub)
{
    do {
        secure_random(seed.data(), seed.size());
    } while (seed[0] == 0);
    pub = ed25519_derive_public(seed);
}

void worker_main(BatchQueue& queue, uint32_t keys_per_batch)
{
    for (;;) {
        Batch batch;
        batch.seeds.resize(keys_per_batch);
        batch.publics.resize(keys_per_batch);
        batch.words.resize(static_cast<size_t>(keys_per_batch) * kKeyWordCount);
        for (uint32_t i = 0; i < keys_per_batch; ++i) {
            generate_key(batch.seeds[i], batch.publics[i]);
            sha1_key_words(batch.publics[i].data(), &batch.words[static_cast<size_t>(i) * kKeyWordCount]);
        }
        if (!queue.push(batch)) {
            wipe_batch(batch);
            return;
        }
    }
}

bool run_gpu_self_test(uint32_t first_timestamp, uint64_t window, std::string& error)
{
    Ed25519Seed seed;
    Ed25519Public pub;
    generate_key(seed, pub);
    secure_wipe(seed.data(), seed.size());

    const uint64_t span = std::min<uint64_t>(window, 1ull << 28);
    uint8_t random_bytes[8];
    secure_random(random_bytes, sizeof(random_bytes));
    uint64_t random_value = 0;
    for (uint8_t b : random_bytes) {
        random_value = (random_value << 8) | b;
    }
    const uint32_t timestamp = first_timestamp + static_cast<uint32_t>(random_value % span);

    const Sha1Digest fingerprint = openpgp_fingerprint(pub, timestamp);
    Pattern exact;
    if (!parse_pattern(to_hex(fingerprint.data(), fingerprint.size()), exact, error)) {
        return false;
    }
    std::vector<uint32_t> words(kKeyWordCount);
    sha1_key_words(pub.data(), words.data());

    std::vector<GpuHit> hits;
    uint32_t total_hits = 0;
    if (!gpu_run(words, 1, first_timestamp, span, exact.target, hits, total_hits, error)) {
        return false;
    }
    for (const GpuHit& hit : hits) {
        if (hit.key == 0 && hit.timestamp == timestamp) {
            return true;
        }
    }
    error = "the GPU search kernel did not find a known fingerprint";
    return false;
}

void clear_progress_line()
{
    std::fprintf(stderr, "\r%*s\r", 110, "");
}

bool emit_result(const Options& options, uint32_t index, const Ed25519Seed& seed, const Ed25519Public& pub, uint32_t created,
                 const Sha1Digest& fingerprint)
{
    std::string armored = openpgp_armored_secret_key(seed, pub, created, options.user_id);
    const std::string fingerprint_hex = to_hex(fingerprint.data(), fingerprint.size());

    clear_progress_line();
    std::cout << "\n=== match " << index << " ===\n"
              << "fingerprint : " << fingerprint_hex << '\n'
              << "key id      : " << fingerprint_hex.substr(24) << '\n'
              << "created     : " << format_time(created) << " (unix " << created << ")\n";

    bool saved = false;
    if (!options.output.empty()) {
        std::string error;
        saved = append_private_file(options.output, armored, error);
        if (saved) {
            std::cout << "saved to    : " << options.output << '\n';
        } else {
            std::cerr << "error: " << error << "; the private key is printed below instead\n";
        }
    }
    if (!saved || !options.hide_secret) {
        std::string seed_hex = to_hex(seed.data(), seed.size());
        std::cout << "private key : " << seed_hex << "\n\n" << armored;
        secure_wipe(&seed_hex[0], seed_hex.size());
    }
    std::cout << std::flush;
    secure_wipe(&armored[0], armored.size());
    return saved || options.output.empty();
}

}

int main(int argc, char** argv)
{
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif
    const std::vector<std::string> args = collect_arguments(argc, argv);
    Options options;
    std::string error;
    if (!parse_options(args, options, error)) {
        std::cerr << "error: " << error << "\n\n";
        print_usage(std::cerr);
        return 2;
    }
    if (options.help) {
        print_usage(std::cout);
        return 0;
    }

    Pattern pattern;
    if (!parse_pattern(options.pattern, pattern, error)) {
        std::cerr << "error: " << error << "\n";
        return 2;
    }

    if (!secure_random_self_check()) {
        std::cerr << "error: the operating system random number generator failed its sanity check\n";
        return 1;
    }

    const uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    if (options.to_time > now) {
        std::cerr << "warning: --to is in the future; GnuPG rejects keys created in the future until that time\n";
    }
    const uint64_t window = static_cast<uint64_t>(options.to_time) - options.from_time + 1;

    GpuInfo gpu_info;
    if (!gpu_init(options.device, gpu_info, error)) {
        std::cerr << "error: " << error << "\n";
        return 1;
    }
    ed25519_warm_up();

    const double expected_attempts = std::ldexp(1.0, 4 * pattern.fixed_digits);
    std::printf("device       : %s (sm_%d%d, %d multiprocessors)\n", gpu_info.name.c_str(), gpu_info.major, gpu_info.minor,
                gpu_info.multiprocessors);
    std::printf("pattern      : %s\n", pattern.display.c_str());
    std::printf("fixed digits : %d (about %.3e fingerprints per match)\n", pattern.fixed_digits, expected_attempts);
    std::printf("time window  : %s .. %s (%llu creation times per key)\n", format_time(options.from_time).c_str(),
                format_time(options.to_time).c_str(), static_cast<unsigned long long>(window));
    std::printf("user id      : %s\n", options.user_id.c_str());
    std::fflush(stdout);

    if (!run_gpu_self_test(options.from_time, window, error)) {
        std::cerr << "error: GPU self-test failed: " << error << "\n";
        gpu_shutdown();
        return 1;
    }
    std::printf("self-test    : passed\n\n");
    std::fflush(stdout);

    const uint32_t keys_per_launch = static_cast<uint32_t>(std::clamp<uint64_t>(kLaunchWork / window, 1, kGpuMaxKeys));
    const uint64_t chunk = std::min<uint64_t>(window, std::max<uint64_t>(1, kLaunchWork / keys_per_launch));

    unsigned thread_count = options.threads;
    if (thread_count == 0) {
        thread_count = std::max(1u, std::thread::hardware_concurrency());
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    BatchQueue queue(kQueueCapacity);
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < thread_count; ++i) {
        workers.emplace_back(worker_main, std::ref(queue), keys_per_launch);
    }

    const auto start = std::chrono::steady_clock::now();
    auto last_report = start;
    uint64_t hashes = 0;
    uint64_t keys_done = 0;
    uint32_t found = 0;
    bool failed = false;
    std::vector<GpuHit> hits;

    auto report = [&](bool force) {
        const auto current = std::chrono::steady_clock::now();
        if (!force && current - last_report < std::chrono::seconds(1)) {
            return;
        }
        last_report = current;
        const double elapsed = std::chrono::duration<double>(current - start).count();
        const double rate = elapsed > 0.0 ? static_cast<double>(hashes) / elapsed : 0.0;
        const double eta = rate > 0.0 ? expected_attempts / rate : 0.0;
        std::fprintf(stderr, "\r[%s] %.2f GH/s | %.3e checked | %llu keys | ~%s per match expected   ",
                     format_duration(elapsed).c_str(), rate / 1e9, static_cast<double>(hashes),
                     static_cast<unsigned long long>(keys_done), format_duration(eta).c_str());
    };

    while (!g_stop.load() && found < options.count && !failed) {
        Batch batch;
        if (!queue.pop(batch)) {
            break;
        }
        for (uint64_t offset = 0; offset < window && !g_stop.load() && found < options.count; offset += chunk) {
            const uint64_t span = std::min<uint64_t>(chunk, window - offset);
            uint32_t total_hits = 0;
            if (!gpu_run(batch.words, keys_per_launch, options.from_time + static_cast<uint32_t>(offset), span, pattern.target, hits,
                         total_hits, error)) {
                clear_progress_line();
                std::cerr << "error: " << error << "\n";
                failed = true;
                break;
            }
            hashes += span * keys_per_launch;
            for (const GpuHit& hit : hits) {
                if (found >= options.count) {
                    break;
                }
                if (hit.key >= keys_per_launch) {
                    continue;
                }
                const Ed25519Public& pub = batch.publics[hit.key];
                const Sha1Digest fingerprint = openpgp_fingerprint(pub, hit.timestamp);
                if (!pattern_matches(pattern, fingerprint)) {
                    clear_progress_line();
                    std::cerr << "warning: discarded a GPU result that failed CPU verification\n";
                    continue;
                }
                ++found;
                emit_result(options, found, batch.seeds[hit.key], pub, hit.timestamp, fingerprint);
            }
            report(false);
        }
        keys_done += keys_per_launch;
        wipe_batch(batch);
        report(false);
    }

    queue.close();
    for (std::thread& worker : workers) {
        worker.join();
    }
    gpu_shutdown();

    report(true);
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::fprintf(stderr, "\n%u match(es) in %s, %.3e fingerprints checked\n", found, format_duration(elapsed).c_str(),
                 static_cast<double>(hashes));
    return (found > 0 && !failed) ? 0 : 1;
}
