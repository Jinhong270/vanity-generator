#pragma once

#include <cstdint>

#if defined(__CUDACC__)
#define VG_HOST_DEVICE __host__ __device__ __forceinline__
#else
#define VG_HOST_DEVICE inline
#endif

#if defined(__CUDA_ARCH__)
#define VG_UNROLL _Pragma("unroll")
#else
#define VG_UNROLL
#endif

constexpr int kKeyWordCount = 9;

struct Sha1Target {
    uint32_t value[5];
    uint32_t mask[5];
};

VG_HOST_DEVICE uint32_t sha1_rotl(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

VG_HOST_DEVICE void sha1_key_words(const uint8_t* pub, uint32_t* words)
{
    words[0] = 0x07400000u | (uint32_t(pub[0]) << 8) | uint32_t(pub[1]);
    for (int i = 0; i < 7; ++i) {
        const uint8_t* p = pub + 2 + 4 * i;
        words[1 + i] = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }
    words[8] = (uint32_t(pub[30]) << 24) | (uint32_t(pub[31]) << 16) | 0x00008000u;
}

VG_HOST_DEVICE void sha1_key_digest(const uint32_t* key_words, uint32_t timestamp, uint32_t* digest)
{
    uint32_t w[16];
    w[0] = 0x99003304u;
    w[1] = timestamp;
    w[2] = 0x16092B06u;
    w[3] = 0x010401DAu;
    w[4] = 0x470F0101u;
    for (int i = 0; i < kKeyWordCount; ++i) {
        w[5 + i] = key_words[i];
    }
    w[14] = 0u;
    w[15] = 0x000001B0u;

    uint32_t a = 0x67452301u;
    uint32_t b = 0xEFCDAB89u;
    uint32_t c = 0x98BADCFEu;
    uint32_t d = 0x10325476u;
    uint32_t e = 0xC3D2E1F0u;

    VG_UNROLL
    for (int i = 0; i < 80; ++i) {
        uint32_t wi;
        if (i < 16) {
            wi = w[i];
        } else {
            wi = sha1_rotl(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15], 1);
            w[i & 15] = wi;
        }
        uint32_t f;
        uint32_t k;
        if (i < 20) {
            f = d ^ (b & (c ^ d));
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (d & (b | c));
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        const uint32_t temp = sha1_rotl(a, 5) + f + e + k + wi;
        e = d;
        d = c;
        c = sha1_rotl(b, 30);
        b = a;
        a = temp;
    }

    digest[0] = a + 0x67452301u;
    digest[1] = b + 0xEFCDAB89u;
    digest[2] = c + 0x98BADCFEu;
    digest[3] = d + 0x10325476u;
    digest[4] = e + 0xC3D2E1F0u;
}

VG_HOST_DEVICE bool sha1_target_hit(const uint32_t* digest, const Sha1Target& target)
{
    const uint32_t diff = ((digest[0] ^ target.value[0]) & target.mask[0]) |
                          ((digest[1] ^ target.value[1]) & target.mask[1]) |
                          ((digest[2] ^ target.value[2]) & target.mask[2]) |
                          ((digest[3] ^ target.value[3]) & target.mask[3]) |
                          ((digest[4] ^ target.value[4]) & target.mask[4]);
    return diff == 0u;
}
