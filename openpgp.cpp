#include "openpgp.h"

#include <vector>

#include "secure.h"

namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint8_t kEd25519Oid[9] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01};
constexpr uint8_t kAlgorithmEdDsa = 22;
constexpr uint8_t kHashSha256 = 8;
constexpr uint8_t kSignatureCertification = 0x13;

void put_u16(Bytes& out, size_t v)
{
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void put_u32(Bytes& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void put_bytes(Bytes& out, const uint8_t* data, size_t size)
{
    out.insert(out.end(), data, data + size);
}

void put_mpi(Bytes& out, const uint8_t* data, size_t size)
{
    while (size > 0 && *data == 0) {
        ++data;
        --size;
    }
    if (size == 0) {
        put_u16(out, 0);
        return;
    }
    size_t bits = (size - 1) * 8;
    for (uint8_t top = data[0]; top != 0; top = static_cast<uint8_t>(top >> 1)) {
        ++bits;
    }
    put_u16(out, bits);
    put_bytes(out, data, size);
}

void put_subpacket(Bytes& out, uint8_t type, const Bytes& data)
{
    out.push_back(static_cast<uint8_t>(data.size() + 1));
    out.push_back(type);
    out.insert(out.end(), data.begin(), data.end());
}

void put_packet(Bytes& out, uint8_t tag, const Bytes& body)
{
    out.push_back(static_cast<uint8_t>(0xC0 | tag));
    const size_t n = body.size();
    if (n < 192) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n < 8384) {
        out.push_back(static_cast<uint8_t>(((n - 192) >> 8) + 192));
        out.push_back(static_cast<uint8_t>((n - 192) & 0xFF));
    } else {
        out.push_back(0xFF);
        put_u32(out, static_cast<uint32_t>(n));
    }
    out.insert(out.end(), body.begin(), body.end());
}

Bytes public_key_body(const Ed25519Public& pub, uint32_t created)
{
    Bytes body;
    body.push_back(4);
    put_u32(body, created);
    body.push_back(kAlgorithmEdDsa);
    body.push_back(static_cast<uint8_t>(sizeof(kEd25519Oid)));
    put_bytes(body, kEd25519Oid, sizeof(kEd25519Oid));
    uint8_t point[33];
    point[0] = 0x40;
    for (size_t i = 0; i < pub.size(); ++i) {
        point[1 + i] = pub[i];
    }
    put_mpi(body, point, sizeof(point));
    return body;
}

Bytes secret_key_body(const Ed25519Seed& seed, const Ed25519Public& pub, uint32_t created)
{
    Bytes body = public_key_body(pub, created);
    body.push_back(0);
    Bytes secret;
    put_mpi(secret, seed.data(), seed.size());
    uint32_t checksum = 0;
    for (uint8_t v : secret) {
        checksum += v;
    }
    body.insert(body.end(), secret.begin(), secret.end());
    put_u16(body, checksum & 0xFFFFu);
    secure_wipe(secret.data(), secret.size());
    return body;
}

uint32_t crc24(const Bytes& data)
{
    uint32_t crc = 0xB704CEu;
    for (uint8_t byte : data) {
        crc ^= static_cast<uint32_t>(byte) << 16;
        for (int i = 0; i < 8; ++i) {
            crc <<= 1;
            if (crc & 0x1000000u) {
                crc ^= 0x1864CFBu;
            }
        }
    }
    return crc & 0xFFFFFFu;
}

std::string base64_encode(const uint8_t* data, size_t size)
{
    static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < size; i += 3) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < size) {
            v |= static_cast<uint32_t>(data[i + 1]) << 8;
        }
        if (i + 2 < size) {
            v |= data[i + 2];
        }
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
        out.push_back(i + 1 < size ? kAlphabet[(v >> 6) & 63] : '=');
        out.push_back(i + 2 < size ? kAlphabet[v & 63] : '=');
    }
    return out;
}

std::string armor(const Bytes& data, const char* label)
{
    std::string out = "-----BEGIN ";
    out += label;
    out += "-----\n\n";
    const std::string body = base64_encode(data.data(), data.size());
    for (size_t i = 0; i < body.size(); i += 64) {
        out += body.substr(i, 64);
        out += '\n';
    }
    const uint32_t crc = crc24(data);
    const uint8_t crc_bytes[3] = {static_cast<uint8_t>(crc >> 16), static_cast<uint8_t>(crc >> 8), static_cast<uint8_t>(crc)};
    out += '=';
    out += base64_encode(crc_bytes, sizeof(crc_bytes));
    out += "\n-----END ";
    out += label;
    out += "-----\n";
    return out;
}

}

Sha1Digest openpgp_fingerprint(const Ed25519Public& pub, uint32_t created)
{
    const Bytes body = public_key_body(pub, created);
    Bytes message;
    message.push_back(0x99);
    put_u16(message, body.size());
    message.insert(message.end(), body.begin(), body.end());
    return sha1(message.data(), message.size());
}

std::string openpgp_armored_secret_key(const Ed25519Seed& seed, const Ed25519Public& pub, uint32_t created, const std::string& user_id)
{
    const Bytes key_body = public_key_body(pub, created);
    const Sha1Digest fingerprint = openpgp_fingerprint(pub, created);
    const Bytes uid(user_id.begin(), user_id.end());

    Bytes signature_body;
    for (uint32_t signature_time = created;; ++signature_time) {
        Bytes hashed;
        Bytes issuer_fingerprint;
        issuer_fingerprint.push_back(4);
        issuer_fingerprint.insert(issuer_fingerprint.end(), fingerprint.begin(), fingerprint.end());
        put_subpacket(hashed, 33, issuer_fingerprint);
        Bytes creation_time;
        put_u32(creation_time, signature_time);
        put_subpacket(hashed, 2, creation_time);
        put_subpacket(hashed, 27, Bytes{0x03});
        put_subpacket(hashed, 11, Bytes{9, 8, 7, 2});
        put_subpacket(hashed, 21, Bytes{10, 9, 8, 11, 2});
        put_subpacket(hashed, 22, Bytes{2, 3, 1});
        put_subpacket(hashed, 30, Bytes{1});
        put_subpacket(hashed, 23, Bytes{0x80});

        Bytes unhashed;
        put_subpacket(unhashed, 16, Bytes(fingerprint.end() - 8, fingerprint.end()));

        Bytes header;
        header.push_back(4);
        header.push_back(kSignatureCertification);
        header.push_back(kAlgorithmEdDsa);
        header.push_back(kHashSha256);
        put_u16(header, hashed.size());
        header.insert(header.end(), hashed.begin(), hashed.end());

        Bytes signed_data;
        signed_data.push_back(0x99);
        put_u16(signed_data, key_body.size());
        signed_data.insert(signed_data.end(), key_body.begin(), key_body.end());
        signed_data.push_back(0xB4);
        put_u32(signed_data, static_cast<uint32_t>(uid.size()));
        signed_data.insert(signed_data.end(), uid.begin(), uid.end());
        signed_data.insert(signed_data.end(), header.begin(), header.end());
        signed_data.push_back(4);
        signed_data.push_back(0xFF);
        put_u32(signed_data, static_cast<uint32_t>(header.size()));

        const Sha256Digest digest = sha256(signed_data.data(), signed_data.size());
        const Ed25519Signature signature = ed25519_sign(seed, pub, digest.data(), digest.size());
        if (signature[0] == 0 || signature[32] == 0) {
            continue;
        }

        signature_body = header;
        put_u16(signature_body, unhashed.size());
        signature_body.insert(signature_body.end(), unhashed.begin(), unhashed.end());
        signature_body.push_back(digest[0]);
        signature_body.push_back(digest[1]);
        put_mpi(signature_body, signature.data(), 32);
        put_mpi(signature_body, signature.data() + 32, 32);
        break;
    }

    Bytes secret_body = secret_key_body(seed, pub, created);
    Bytes packets;
    put_packet(packets, 5, secret_body);
    put_packet(packets, 13, uid);
    put_packet(packets, 2, signature_body);
    const std::string armored = armor(packets, "PGP PRIVATE KEY BLOCK");
    secure_wipe(secret_body.data(), secret_body.size());
    secure_wipe(packets.data(), packets.size());
    return armored;
}
