#include "Ascon.h"

namespace ascon
{

namespace
{

constexpr uint64_t kAead128Iv = 0x00001000808c0001ULL; // Ascon-AEAD128: a = 12, b = 8, tag 128, rate 16 bytes
constexpr uint64_t kHash256Iv = 0x0000080100cc0002ULL; // Ascon-Hash256: a = b = 12, digest 256, rate 8 bytes
constexpr size_t kAeadRate = 16;
constexpr size_t kHashRate = 8;

struct State
{
    uint64_t x[5];
};

uint64_t ror(uint64_t x, int n)
{
    return (x >> n) | (x << (64 - n));
}

// little-endian load / store of n <= 8 bytes (SP 800-232 byte order)
uint64_t load(const uint8_t* bytes, size_t n)
{
    uint64_t x = 0;
    for (size_t i = 0; i < n; ++i) {
        x |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    }
    return x;
}

void store(uint8_t* bytes, uint64_t x, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        bytes[i] = static_cast<uint8_t>(x >> (8 * i));
    }
}

// padding byte 0x01 right after the last of i bytes in a word
uint64_t pad(size_t i)
{
    return 0x01ULL << (8 * i);
}

void applyRound(State& s, uint8_t c)
{
    // round constant
    s.x[2] ^= c;
    // substitution layer (bitsliced 5-bit S-box)
    s.x[0] ^= s.x[4];
    s.x[4] ^= s.x[3];
    s.x[2] ^= s.x[1];
    uint64_t t[5];
    t[0] = s.x[0] ^ (~s.x[1] & s.x[2]);
    t[1] = s.x[1] ^ (~s.x[2] & s.x[3]);
    t[2] = s.x[2] ^ (~s.x[3] & s.x[4]);
    t[3] = s.x[3] ^ (~s.x[4] & s.x[0]);
    t[4] = s.x[4] ^ (~s.x[0] & s.x[1]);
    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];
    t[2] = ~t[2];
    // linear diffusion layer
    s.x[0] = t[0] ^ ror(t[0], 19) ^ ror(t[0], 28);
    s.x[1] = t[1] ^ ror(t[1], 61) ^ ror(t[1], 39);
    s.x[2] = t[2] ^ ror(t[2], 1) ^ ror(t[2], 6);
    s.x[3] = t[3] ^ ror(t[3], 10) ^ ror(t[3], 17);
    s.x[4] = t[4] ^ ror(t[4], 7) ^ ror(t[4], 41);
}

// p^rounds: the last "rounds" of the 12 round constants
void permute(State& s, int rounds)
{
    static constexpr uint8_t kConstants[12] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
    };
    for (int i = 12 - rounds; i < 12; ++i) {
        applyRound(s, kConstants[i]);
    }
}

// the state holds key-dependent values: wipe it in a way the compiler cannot drop
void wipe(State& s)
{
    volatile uint64_t* x = s.x;
    for (int i = 0; i < 5; ++i) {
        x[i] = 0;
    }
}

} // namespace

Digest hash256(const uint8_t* data, size_t size)
{
    State s{ { kHash256Iv, 0, 0, 0, 0 } };
    permute(s, 12);

    while (size >= kHashRate) {
        s.x[0] ^= load(data, kHashRate);
        permute(s, 12);
        data += kHashRate;
        size -= kHashRate;
    }
    s.x[0] ^= load(data, size) ^ pad(size);
    permute(s, 12);

    Digest digest;
    for (size_t i = 0; i < digest.size(); i += kHashRate) {
        if (i > 0) {
            permute(s, 12);
        }
        store(digest.data() + i, s.x[0], kHashRate);
    }
    wipe(s);
    return digest;
}

Tag aead128Tag(const Key& key, const Nonce& nonce, const uint8_t* ad, size_t adSize)
{
    const uint64_t k0 = load(key.data(), 8);
    const uint64_t k1 = load(key.data() + 8, 8);

    // initialization: S = IV || K || N, p^12, S ^= 0^192 || K
    State s{ { kAead128Iv, k0, k1, load(nonce.data(), 8), load(nonce.data() + 8, 8) } };
    permute(s, 12);
    s.x[3] ^= k0;
    s.x[4] ^= k1;

    // associated data: 16-byte blocks, the last one padded; skipped entirely when empty
    if (adSize > 0) {
        while (adSize >= kAeadRate) {
            s.x[0] ^= load(ad, 8);
            s.x[1] ^= load(ad + 8, 8);
            permute(s, 8);
            ad += kAeadRate;
            adSize -= kAeadRate;
        }
        if (adSize >= 8) {
            s.x[0] ^= load(ad, 8);
            s.x[1] ^= load(ad + 8, adSize - 8) ^ pad(adSize - 8);
        } else {
            s.x[0] ^= load(ad, adSize) ^ pad(adSize);
        }
        permute(s, 8);
    }

    // domain separation
    s.x[4] ^= 0x80ULL << 56;

    // empty plaintext: only its padding block
    s.x[0] ^= pad(0);

    // finalization: S ^= 0^128 || K || 0^64, p^12, T = S[192..319] ^ K
    s.x[2] ^= k0;
    s.x[3] ^= k1;
    permute(s, 12);
    Tag tag;
    store(tag.data(), s.x[3] ^ k0, 8);
    store(tag.data() + 8, s.x[4] ^ k1, 8);
    wipe(s);
    return tag;
}

} // namespace ascon
