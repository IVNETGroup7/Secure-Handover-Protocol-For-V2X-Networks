#ifndef COMMON_ASCON_H_
#define COMMON_ASCON_H_

#include <array>
#include <cstddef>
#include <cstdint>

namespace ascon
{

using Key = std::array<uint8_t, 16>;
using Nonce = std::array<uint8_t, 16>;
using Tag = std::array<uint8_t, 16>;
using Digest = std::array<uint8_t, 32>;

// Ascon-Hash256
Digest hash256(const uint8_t* data, size_t size);

// Ascon-AEAD128 encryption of an empty plaintext: the 16-byte tag authenticates the associated data "ad"
// under (key, nonce), i.e. Ascon used as a nonce-based MAC. (key, nonce) must not be reused for another "ad".
Tag aead128Tag(const Key& key, const Nonce& nonce, const uint8_t* ad, size_t adSize);

} // namespace ascon

#endif /* COMMON_ASCON_H_ */
