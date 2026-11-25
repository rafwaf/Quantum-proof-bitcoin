// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SLHDSA_H
#define BITCOIN_CRYPTO_SLHDSA_H

#include <cstddef>
#include <span>

/** SLH-DSA-SHA2-128s, the stateless hash-based signature scheme specified in
 *  NIST FIPS 205 (https://doi.org/10.6028/NIST.FIPS.205).
 *
 *  Only the SHA2-128s parameter set is implemented. Its security rests solely
 *  on SHA-256, and it has the smallest signatures of the standardized sets.
 *
 *  Function and variable names follow the standard, and the comments refer to
 *  its algorithm numbers.
 */
namespace slhdsa {

/** The security parameter n: the length in bytes of every hash value used. */
inline constexpr size_t N{16};
/** Size of a public key: PK.seed || PK.root. */
inline constexpr size_t PUBLIC_KEY_SIZE{2 * N};
/** Size of a secret key: SK.seed || SK.prf || PK.seed || PK.root. */
inline constexpr size_t SECRET_KEY_SIZE{4 * N};
/** Size of a signature. */
inline constexpr size_t SIGNATURE_SIZE{7856};
/** Maximum length of the context string of the external interface. */
inline constexpr size_t MAX_CONTEXT_SIZE{255};

/** Derive a key pair from three n-byte seeds (FIPS 205 Algorithm 18,
 *  slh_keygen_internal). The seeds must come from a cryptographically secure
 *  random source and be independent of each other. */
void KeyGen(std::span<const unsigned char, N> sk_seed,
            std::span<const unsigned char, N> sk_prf,
            std::span<const unsigned char, N> pk_seed,
            std::span<unsigned char, SECRET_KEY_SIZE> secret_key,
            std::span<unsigned char, PUBLIC_KEY_SIZE> public_key);

/** Sign a message (FIPS 205 Algorithm 22, slh_sign: the "pure" variant).
 *
 *  @param[in]  msg         The message to sign.
 *  @param[in]  context     Context string for domain separation, at most
 *                          MAX_CONTEXT_SIZE bytes. May be empty.
 *  @param[in]  secret_key  The secret key.
 *  @param[in]  addrnd      Either N bytes of fresh randomness (the hedged
 *                          variant, which the standard recommends), or empty
 *                          for the deterministic variant.
 *  @param[out] signature   The signature.
 *  @return false if the context is too long, in which case nothing is signed.
 */
[[nodiscard]] bool Sign(std::span<const unsigned char> msg,
                        std::span<const unsigned char> context,
                        std::span<const unsigned char, SECRET_KEY_SIZE> secret_key,
                        std::span<const unsigned char> addrnd,
                        std::span<unsigned char, SIGNATURE_SIZE> signature);

/** Verify a signature (FIPS 205 Algorithm 24, slh_verify: the "pure" variant).
 *
 *  Returns false for a signature of the wrong length, a context that is too
 *  long, or a signature that does not verify. */
[[nodiscard]] bool Verify(std::span<const unsigned char> msg,
                          std::span<const unsigned char> signature,
                          std::span<const unsigned char> context,
                          std::span<const unsigned char, PUBLIC_KEY_SIZE> public_key);

/** Sign without the message encoding of the external interface (FIPS 205
 *  Algorithm 19, slh_sign_internal). Exposed for testing against the NIST
 *  test vectors; use Sign() otherwise. */
void SignInternal(std::span<const unsigned char> msg,
                  std::span<const unsigned char, SECRET_KEY_SIZE> secret_key,
                  std::span<const unsigned char> addrnd,
                  std::span<unsigned char, SIGNATURE_SIZE> signature);

/** Verify without the message encoding of the external interface (FIPS 205
 *  Algorithm 20, slh_verify_internal). Exposed for testing against the NIST
 *  test vectors; use Verify() otherwise. */
[[nodiscard]] bool VerifyInternal(std::span<const unsigned char> msg,
                                  std::span<const unsigned char> signature,
                                  std::span<const unsigned char, PUBLIC_KEY_SIZE> public_key);

} // namespace slhdsa

#endif // BITCOIN_CRYPTO_SLHDSA_H
