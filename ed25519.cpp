#include "ed25519.h"

#include <memory>
#include <vector>

#include "hash.h"
#include "secure.h"

namespace {

struct Fe {
    int64_t v[16];
};

struct Point {
    Fe x, y, z, t;
};

constexpr Fe kZero = {{0}};
constexpr Fe kOne = {{1}};
constexpr Fe kD2 = {{0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406}};
constexpr Fe kBaseX = {{0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169}};
constexpr Fe kBaseY = {{0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666}};

void fe_carry(Fe& o)
{
    for (int i = 0; i < 16; ++i) {
        o.v[i] += int64_t(1) << 16;
        const int64_t c = o.v[i] >> 16;
        o.v[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o.v[i] -= c * 65536;
    }
}

void fe_select(Fe& p, Fe& q, int64_t b)
{
    const int64_t c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        const int64_t t = c & (p.v[i] ^ q.v[i]);
        p.v[i] ^= t;
        q.v[i] ^= t;
    }
}

void fe_pack(uint8_t* out, const Fe& n)
{
    Fe m;
    Fe t = n;
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);
    for (int j = 0; j < 2; ++j) {
        m.v[0] = t.v[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m.v[i] = t.v[i] - 0xffff - ((m.v[i - 1] >> 16) & 1);
            m.v[i - 1] &= 0xffff;
        }
        m.v[15] = t.v[15] - 0x7fff - ((m.v[14] >> 16) & 1);
        const int64_t b = (m.v[15] >> 16) & 1;
        m.v[14] &= 0xffff;
        fe_select(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        out[2 * i] = static_cast<uint8_t>(t.v[i] & 0xff);
        out[2 * i + 1] = static_cast<uint8_t>(t.v[i] >> 8);
    }
}

void fe_add(Fe& o, const Fe& a, const Fe& b)
{
    for (int i = 0; i < 16; ++i) {
        o.v[i] = a.v[i] + b.v[i];
    }
}

void fe_sub(Fe& o, const Fe& a, const Fe& b)
{
    for (int i = 0; i < 16; ++i) {
        o.v[i] = a.v[i] - b.v[i];
    }
}

void fe_mul(Fe& o, const Fe& a, const Fe& b)
{
    int64_t t[31] = {};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a.v[i] * b.v[j];
        }
    }
    for (int i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; ++i) {
        o.v[i] = t[i];
    }
    fe_carry(o);
    fe_carry(o);
}

void fe_invert(Fe& o, const Fe& in)
{
    Fe c = in;
    for (int a = 253; a >= 0; --a) {
        fe_mul(c, c, c);
        if (a != 2 && a != 4) {
            fe_mul(c, c, in);
        }
    }
    o = c;
}

void point_add(Point& p, const Point& q)
{
    Fe a, b, c, d, t, e, f, g, h;
    fe_sub(a, p.y, p.x);
    fe_sub(t, q.y, q.x);
    fe_mul(a, a, t);
    fe_add(b, p.x, p.y);
    fe_add(t, q.x, q.y);
    fe_mul(b, b, t);
    fe_mul(c, p.t, q.t);
    fe_mul(c, c, kD2);
    fe_mul(d, p.z, q.z);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(p.x, e, f);
    fe_mul(p.y, h, g);
    fe_mul(p.z, g, f);
    fe_mul(p.t, e, h);
}

void point_pack(uint8_t* out, const Point& p)
{
    Fe zi, tx, ty;
    fe_invert(zi, p.z);
    fe_mul(tx, p.x, zi);
    fe_mul(ty, p.y, zi);
    fe_pack(out, ty);
    uint8_t parity[32];
    fe_pack(parity, tx);
    out[31] ^= static_cast<uint8_t>((parity[0] & 1) << 7);
}

struct BaseTable {
    Point entry[64][16];
};

const BaseTable& base_table()
{
    static const std::unique_ptr<BaseTable> table = [] {
        auto result = std::make_unique<BaseTable>();
        Point identity;
        identity.x = kZero;
        identity.y = kOne;
        identity.z = kOne;
        identity.t = kZero;
        Point current;
        current.x = kBaseX;
        current.y = kBaseY;
        current.z = kOne;
        fe_mul(current.t, kBaseX, kBaseY);
        for (int i = 0; i < 64; ++i) {
            result->entry[i][0] = identity;
            result->entry[i][1] = current;
            for (int j = 2; j < 16; ++j) {
                result->entry[i][j] = result->entry[i][j - 1];
                point_add(result->entry[i][j], current);
            }
            for (int k = 0; k < 4; ++k) {
                point_add(current, current);
            }
        }
        return result;
    }();
    return *table;
}

void point_select(Point& out, const Point* candidates, unsigned index)
{
    for (int limb = 0; limb < 16; ++limb) {
        out.x.v[limb] = 0;
        out.y.v[limb] = 0;
        out.z.v[limb] = 0;
        out.t.v[limb] = 0;
    }
    for (unsigned j = 0; j < 16; ++j) {
        const int64_t mask = -static_cast<int64_t>((static_cast<uint64_t>(j ^ index) - 1) >> 63);
        for (int limb = 0; limb < 16; ++limb) {
            out.x.v[limb] |= candidates[j].x.v[limb] & mask;
            out.y.v[limb] |= candidates[j].y.v[limb] & mask;
            out.z.v[limb] |= candidates[j].z.v[limb] & mask;
            out.t.v[limb] |= candidates[j].t.v[limb] & mask;
        }
    }
}

Point scalar_mult_base(const uint8_t* scalar)
{
    const BaseTable& table = base_table();
    Point p = table.entry[0][0];
    Point selected;
    for (int i = 0; i < 32; ++i) {
        point_select(selected, table.entry[2 * i], scalar[i] & 15u);
        point_add(p, selected);
        point_select(selected, table.entry[2 * i + 1], scalar[i] >> 4);
        point_add(p, selected);
    }
    secure_wipe(&selected, sizeof(selected));
    return p;
}

void clamp_scalar(uint8_t* a)
{
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

using U256 = std::array<uint32_t, 8>;

constexpr U256 kOrder = {0x5cf5d3edu, 0x5812631au, 0xa2f79cd6u, 0x14def9deu, 0u, 0u, 0u, 0x10000000u};

uint32_t u256_sub(U256& a, const U256& b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        const uint64_t d = static_cast<uint64_t>(a[i]) - b[i] - borrow;
        a[i] = static_cast<uint32_t>(d);
        borrow = (d >> 32) & 1;
    }
    return static_cast<uint32_t>(borrow);
}

U256 reduce_mod_order(const uint8_t* bytes, size_t size)
{
    U256 r{};
    for (size_t bit = size * 8; bit-- > 0;) {
        uint32_t carry = (bytes[bit / 8] >> (bit % 8)) & 1u;
        for (int i = 0; i < 8; ++i) {
            const uint32_t next = r[i] >> 31;
            r[i] = (r[i] << 1) | carry;
            carry = next;
        }
        U256 reduced = r;
        const uint32_t keep = 0u - u256_sub(reduced, kOrder);
        for (int i = 0; i < 8; ++i) {
            r[i] = (r[i] & keep) | (reduced[i] & ~keep);
        }
    }
    return r;
}

U256 load_le(const uint8_t* in)
{
    U256 v;
    for (int i = 0; i < 8; ++i) {
        v[i] = uint32_t(in[4 * i]) | (uint32_t(in[4 * i + 1]) << 8) | (uint32_t(in[4 * i + 2]) << 16) | (uint32_t(in[4 * i + 3]) << 24);
    }
    return v;
}

void store_le(const U256& v, uint8_t* out)
{
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            out[4 * i + j] = static_cast<uint8_t>(v[i] >> (8 * j));
        }
    }
}

}

void ed25519_warm_up()
{
    base_table();
}

Ed25519Public ed25519_derive_public(const Ed25519Seed& seed)
{
    Sha512Digest h = sha512(seed.data(), seed.size());
    uint8_t scalar[32];
    for (int i = 0; i < 32; ++i) {
        scalar[i] = h[i];
    }
    clamp_scalar(scalar);
    Point p = scalar_mult_base(scalar);
    Ed25519Public pub;
    point_pack(pub.data(), p);
    secure_wipe(h.data(), h.size());
    secure_wipe(scalar, sizeof(scalar));
    secure_wipe(&p, sizeof(p));
    return pub;
}

Ed25519Signature ed25519_sign(const Ed25519Seed& seed, const Ed25519Public& pub, const uint8_t* message, size_t size)
{
    Sha512Digest h = sha512(seed.data(), seed.size());
    uint8_t scalar[32];
    for (int i = 0; i < 32; ++i) {
        scalar[i] = h[i];
    }
    clamp_scalar(scalar);

    std::vector<uint8_t> buffer(h.begin() + 32, h.end());
    buffer.insert(buffer.end(), message, message + size);
    Sha512Digest r_hash = sha512(buffer.data(), buffer.size());
    U256 r = reduce_mod_order(r_hash.data(), r_hash.size());
    uint8_t r_bytes[32];
    store_le(r, r_bytes);

    Ed25519Signature sig;
    Point r_point = scalar_mult_base(r_bytes);
    point_pack(sig.data(), r_point);

    secure_wipe(buffer.data(), buffer.size());
    buffer.assign(sig.begin(), sig.begin() + 32);
    buffer.insert(buffer.end(), pub.begin(), pub.end());
    buffer.insert(buffer.end(), message, message + size);
    const Sha512Digest k_hash = sha512(buffer.data(), buffer.size());
    const U256 k = reduce_mod_order(k_hash.data(), k_hash.size());

    U256 a = load_le(scalar);
    uint32_t product[16] = {};
    for (int i = 0; i < 8; ++i) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; ++j) {
            const uint64_t t = static_cast<uint64_t>(k[i]) * a[j] + product[i + j] + carry;
            product[i + j] = static_cast<uint32_t>(t);
            carry = t >> 32;
        }
        product[i + 8] = static_cast<uint32_t>(carry);
    }
    uint64_t carry = 0;
    for (int i = 0; i < 16; ++i) {
        const uint64_t t = static_cast<uint64_t>(product[i]) + (i < 8 ? r[i] : 0u) + carry;
        product[i] = static_cast<uint32_t>(t);
        carry = t >> 32;
    }
    uint8_t wide[64];
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 4; ++j) {
            wide[4 * i + j] = static_cast<uint8_t>(product[i] >> (8 * j));
        }
    }
    const U256 s = reduce_mod_order(wide, sizeof(wide));
    store_le(s, sig.data() + 32);

    secure_wipe(h.data(), h.size());
    secure_wipe(scalar, sizeof(scalar));
    secure_wipe(buffer.data(), buffer.size());
    secure_wipe(r_hash.data(), r_hash.size());
    secure_wipe(r.data(), sizeof(r));
    secure_wipe(r_bytes, sizeof(r_bytes));
    secure_wipe(&r_point, sizeof(r_point));
    secure_wipe(a.data(), sizeof(a));
    secure_wipe(product, sizeof(product));
    secure_wipe(wide, sizeof(wide));
    return sig;
}
