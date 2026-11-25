// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa.h>

#include <crypto/common.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>

#include <cassert>
#include <cstdint>
#include <cstring>

namespace slhdsa {
namespace {

// Parameters of SLH-DSA-SHA2-128s (FIPS 205, Table 2).
constexpr unsigned HP{9};       //!< h': height of each XMSS tree.
constexpr unsigned D{7};        //!< d: number of XMSS layers. The total height is h = d * h' = 63.
constexpr unsigned A{12};       //!< a: height of each FORS tree.
constexpr unsigned K{14};       //!< k: number of FORS trees.
constexpr unsigned W{16};       //!< w: the Winternitz parameter, 2^lg_w with lg_w = 4.
constexpr unsigned LEN1{2 * N}; //!< len1: number of base-w digits in an n-byte message.
constexpr unsigned LEN2{3};     //!< len2: number of base-w digits in the checksum.
constexpr unsigned LEN{LEN1 + LEN2};

// Lengths of the three parts of the message digest (FIPS 205 Algorithm 19, lines 7-9).
constexpr size_t MD_SIZE{(K * A + 7) / 8};
constexpr size_t IDX_TREE_SIZE{((D - 1) * HP + 7) / 8};
constexpr size_t IDX_LEAF_SIZE{(HP + 7) / 8};
constexpr size_t DIGEST_SIZE{MD_SIZE + IDX_TREE_SIZE + IDX_LEAF_SIZE}; //!< m

constexpr size_t FORS_SIG_SIZE{K * (1 + A) * N};
constexpr size_t XMSS_SIG_SIZE{(LEN + HP) * N};
constexpr size_t HT_SIG_SIZE{D * XMSS_SIG_SIZE};

static_assert(MD_SIZE == 21 && IDX_TREE_SIZE == 7 && IDX_LEAF_SIZE == 2 && DIGEST_SIZE == 30);
static_assert(N + FORS_SIG_SIZE + HT_SIG_SIZE == SIGNATURE_SIZE);
// H_msg below produces its output with a single SHA-256 call.
static_assert(DIGEST_SIZE <= CSHA256::OUTPUT_SIZE);

/** Address types (FIPS 205 section 4.2). */
enum class AdrsType : uint8_t {
    WOTS_HASH = 0,
    WOTS_PK = 1,
    TREE = 2,
    FORS_TREE = 3,
    FORS_ROOTS = 4,
    WOTS_PRF = 5,
    FORS_PRF = 6,
};

/** A hash function address (ADRS), kept in the 22-byte compressed form that
 *  the SHA2 parameter sets feed to the hash function (ADRSc, FIPS 205 section
 *  11.2):
 *
 *      layer address (1) || tree address (8) || type (1) || three 4-byte words
 *
 *  The meaning of the three words depends on the type.
 */
class Adrs
{
public:
    static constexpr size_t SIZE{22};

    void SetLayer(uint32_t layer) { m_data[0] = static_cast<unsigned char>(layer); }
    void SetTree(uint64_t tree) { WriteBE64(m_data + 1, tree); }
    void SetTypeAndClear(AdrsType type)
    {
        m_data[9] = static_cast<unsigned char>(type);
        std::memset(m_data + 10, 0, 12);
    }
    // First word: the key pair address.
    void SetKeyPair(uint32_t i) { WriteBE32(m_data + 10, i); }
    uint32_t GetKeyPair() const { return ReadBE32(m_data + 10); }
    // Second word: the chain address (WOTS+) or the tree height (XMSS and FORS trees).
    void SetChain(uint32_t i) { WriteBE32(m_data + 14, i); }
    void SetTreeHeight(uint32_t i) { WriteBE32(m_data + 14, i); }
    // Third word: the hash address (WOTS+) or the tree index (XMSS and FORS trees).
    void SetHash(uint32_t i) { WriteBE32(m_data + 18, i); }
    void SetTreeIndex(uint32_t i) { WriteBE32(m_data + 18, i); }
    uint32_t GetTreeIndex() const { return ReadBE32(m_data + 18); }

    const unsigned char* data() const { return m_data; }

private:
    unsigned char m_data[SIZE]{};
};

/** The tweakable hash function shared by F, H, T_l and PRF (FIPS 205 section
 *  11.2.1). For the SHA2 category 1 parameter sets all four are
 *
 *      Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || input))
 *
 *  and differ only in their input. PK.seed and its padding fill exactly one
 *  SHA-256 block, so the state after that block is computed once and reused.
 */
class Hasher
{
public:
    explicit Hasher(std::span<const unsigned char, N> pk_seed)
    {
        unsigned char block[64]{};
        std::memcpy(block, pk_seed.data(), N);
        m_seeded.Write(block, sizeof(block));
    }

    /** Hash input under the given address. out may alias input. */
    void operator()(const Adrs& adrs, std::span<const unsigned char> input, unsigned char* out) const
    {
        unsigned char full[CSHA256::OUTPUT_SIZE];
        CSHA256 hasher{m_seeded};
        hasher.Write(adrs.data(), Adrs::SIZE).Write(input.data(), input.size()).Finalize(full);
        std::memcpy(out, full, N);
    }

private:
    //! SHA-256 state after absorbing PK.seed || toByte(0, 64 - n).
    CSHA256 m_seeded;
};

/** PRF: derive a secret n-byte value from SK.seed and an address. */
void Prf(const Hasher& hash, const Adrs& adrs, const unsigned char* sk_seed, unsigned char* out)
{
    hash(adrs, std::span{sk_seed, N}, out);
}

/** PRF_msg: derive the randomizer R (FIPS 205 section 11.2.1):
 *  Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M)). The message is prefix || msg. */
void PrfMsg(const unsigned char* sk_prf, const unsigned char* opt_rand, std::span<const unsigned char> prefix, std::span<const unsigned char> msg, unsigned char* r)
{
    unsigned char full[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256 hmac{sk_prf, N};
    hmac.Write(opt_rand, N);
    if (!prefix.empty()) hmac.Write(prefix.data(), prefix.size());
    if (!msg.empty()) hmac.Write(msg.data(), msg.size());
    hmac.Finalize(full);
    std::memcpy(r, full, N);
    memory_cleanse(full, sizeof(full));
}

/** H_msg: hash the message to an m-byte digest (FIPS 205 section 11.2.1):
 *  MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m).
 *  The message is prefix || msg. */
void HMsg(const unsigned char* r, std::span<const unsigned char, PUBLIC_KEY_SIZE> pk, std::span<const unsigned char> prefix, std::span<const unsigned char> msg, unsigned char* digest)
{
    unsigned char inner[CSHA256::OUTPUT_SIZE];
    CSHA256 inner_hasher;
    inner_hasher.Write(r, N).Write(pk.data(), PUBLIC_KEY_SIZE);
    if (!prefix.empty()) inner_hasher.Write(prefix.data(), prefix.size());
    if (!msg.empty()) inner_hasher.Write(msg.data(), msg.size());
    inner_hasher.Finalize(inner);

    // MGF1 concatenates SHA-256(seed || counter) for counter = 0, 1, ... and
    // truncates. An m-byte output only needs the block with counter 0.
    static constexpr unsigned char COUNTER_ZERO[4]{0, 0, 0, 0};
    unsigned char block[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(r, N).Write(pk.data(), N).Write(inner, sizeof(inner)).Write(COUNTER_ZERO, sizeof(COUNTER_ZERO)).Finalize(block);
    std::memcpy(digest, block, DIGEST_SIZE);
}

/** Split the message digest into the FORS message (its first MD_SIZE bytes)
 *  and the tree and leaf indices (FIPS 205 Algorithm 19, lines 7-11). */
void SplitDigest(const unsigned char* digest, uint64_t& idx_tree, uint32_t& idx_leaf)
{
    uint64_t tree{0};
    for (size_t i = 0; i < IDX_TREE_SIZE; ++i) tree = (tree << 8) | digest[MD_SIZE + i];
    idx_tree = tree & ((uint64_t{1} << ((D - 1) * HP)) - 1);
    uint32_t leaf{0};
    for (size_t i = 0; i < IDX_LEAF_SIZE; ++i) leaf = (leaf << 8) | digest[MD_SIZE + IDX_TREE_SIZE + i];
    idx_leaf = leaf & ((uint32_t{1} << HP) - 1);
}

/** Algorithm 5, chain: apply F to x s times, starting at step i. out may alias x. */
void Chain(const Hasher& hash, Adrs adrs, const unsigned char* x, unsigned i, unsigned s, unsigned char* out)
{
    unsigned char tmp[N];
    std::memcpy(tmp, x, N);
    for (unsigned j = i; j < i + s; ++j) {
        adrs.SetHash(j);
        hash(adrs, tmp, tmp);
    }
    std::memcpy(out, tmp, N);
}

/** Convert an n-byte message into the len base-w digits that WOTS+ signs: the
 *  message digits followed by the checksum digits (the first lines of FIPS 205
 *  Algorithms 7 and 8). */
void WotsDigits(const unsigned char* msg, unsigned digits[LEN])
{
    unsigned csum{0};
    for (unsigned i = 0; i < N; ++i) {
        digits[2 * i] = msg[i] >> 4;
        digits[2 * i + 1] = msg[i] & 15;
    }
    for (unsigned i = 0; i < LEN1; ++i) csum += W - 1 - digits[i];
    // The standard shifts the checksum left by 4 bits, writes it as 2 bytes
    // and takes the first 3 base-16 digits, which are its 12 low bits.
    static_assert(LEN1 * (W - 1) < (1U << 12));
    digits[LEN1] = (csum >> 8) & 15;
    digits[LEN1 + 1] = (csum >> 4) & 15;
    digits[LEN1 + 2] = csum & 15;
}

/** Algorithm 6, wots_pkGen: compute a WOTS+ public key. */
void WotsPkGen(const Hasher& hash, const unsigned char* sk_seed, Adrs adrs, unsigned char* pk)
{
    Adrs sk_adrs{adrs};
    sk_adrs.SetTypeAndClear(AdrsType::WOTS_PRF);
    sk_adrs.SetKeyPair(adrs.GetKeyPair());
    unsigned char tmp[LEN * N];
    unsigned char sk[N];
    for (unsigned i = 0; i < LEN; ++i) {
        sk_adrs.SetChain(i);
        Prf(hash, sk_adrs, sk_seed, sk);
        adrs.SetChain(i);
        Chain(hash, adrs, sk, 0, W - 1, tmp + i * N);
    }
    Adrs pk_adrs{adrs};
    pk_adrs.SetTypeAndClear(AdrsType::WOTS_PK);
    pk_adrs.SetKeyPair(adrs.GetKeyPair());
    hash(pk_adrs, tmp, pk);
    memory_cleanse(sk, sizeof(sk));
}

/** Algorithm 7, wots_sign: sign an n-byte message with WOTS+. */
void WotsSign(const Hasher& hash, const unsigned char* msg, const unsigned char* sk_seed, Adrs adrs, unsigned char* sig)
{
    unsigned digits[LEN];
    WotsDigits(msg, digits);
    Adrs sk_adrs{adrs};
    sk_adrs.SetTypeAndClear(AdrsType::WOTS_PRF);
    sk_adrs.SetKeyPair(adrs.GetKeyPair());
    unsigned char sk[N];
    for (unsigned i = 0; i < LEN; ++i) {
        sk_adrs.SetChain(i);
        Prf(hash, sk_adrs, sk_seed, sk);
        adrs.SetChain(i);
        Chain(hash, adrs, sk, 0, digits[i], sig + i * N);
    }
    memory_cleanse(sk, sizeof(sk));
}

/** Algorithm 8, wots_pkFromSig: compute a WOTS+ public key from a signature. */
void WotsPkFromSig(const Hasher& hash, const unsigned char* sig, const unsigned char* msg, Adrs adrs, unsigned char* pk)
{
    unsigned digits[LEN];
    WotsDigits(msg, digits);
    unsigned char tmp[LEN * N];
    for (unsigned i = 0; i < LEN; ++i) {
        adrs.SetChain(i);
        Chain(hash, adrs, sig + i * N, digits[i], W - 1 - digits[i], tmp + i * N);
    }
    Adrs pk_adrs{adrs};
    pk_adrs.SetTypeAndClear(AdrsType::WOTS_PK);
    pk_adrs.SetKeyPair(adrs.GetKeyPair());
    hash(pk_adrs, tmp, pk);
}

/** Algorithm 9, xmss_node: compute the node at height z and index i of an XMSS tree. */
void XmssNode(const Hasher& hash, const unsigned char* sk_seed, uint32_t i, unsigned z, Adrs adrs, unsigned char* node)
{
    if (z == 0) {
        adrs.SetTypeAndClear(AdrsType::WOTS_HASH);
        adrs.SetKeyPair(i);
        WotsPkGen(hash, sk_seed, adrs, node);
    } else {
        unsigned char children[2 * N];
        XmssNode(hash, sk_seed, 2 * i, z - 1, adrs, children);
        XmssNode(hash, sk_seed, 2 * i + 1, z - 1, adrs, children + N);
        adrs.SetTypeAndClear(AdrsType::TREE);
        adrs.SetTreeHeight(z);
        adrs.SetTreeIndex(i);
        hash(adrs, children, node);
    }
}

/** Algorithm 10, xmss_sign: sign an n-byte message with the leaf idx of an
 *  XMSS tree. The signature is the WOTS+ signature followed by the
 *  authentication path. */
void XmssSign(const Hasher& hash, const unsigned char* msg, const unsigned char* sk_seed, uint32_t idx, Adrs adrs, unsigned char* sig)
{
    unsigned char* auth{sig + LEN * N};
    for (unsigned j = 0; j < HP; ++j) {
        const uint32_t k{(idx >> j) ^ 1};
        XmssNode(hash, sk_seed, k, j, adrs, auth + j * N);
    }
    adrs.SetTypeAndClear(AdrsType::WOTS_HASH);
    adrs.SetKeyPair(idx);
    WotsSign(hash, msg, sk_seed, adrs, sig);
}

/** Climb from a node to the root of a tree of the given height along an
 *  authentication path (the loops of FIPS 205 Algorithms 11 and 17). On entry
 *  the address holds the node's tree index, with any offset common to the
 *  tree. node is updated in place. */
void ClimbTree(const Hasher& hash, Adrs& adrs, uint32_t idx, const unsigned char* auth, unsigned height, unsigned char* node)
{
    for (unsigned k = 0; k < height; ++k) {
        adrs.SetTreeHeight(k + 1);
        unsigned char pair[2 * N];
        if (((idx >> k) & 1) == 0) {
            adrs.SetTreeIndex(adrs.GetTreeIndex() / 2);
            std::memcpy(pair, node, N);
            std::memcpy(pair + N, auth + k * N, N);
        } else {
            adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2);
            std::memcpy(pair, auth + k * N, N);
            std::memcpy(pair + N, node, N);
        }
        hash(adrs, pair, node);
    }
}

/** Algorithm 11, xmss_pkFromSig: compute the root of an XMSS tree from a
 *  signature. root may alias msg. */
void XmssPkFromSig(const Hasher& hash, uint32_t idx, const unsigned char* sig, const unsigned char* msg, Adrs adrs, unsigned char* root)
{
    adrs.SetTypeAndClear(AdrsType::WOTS_HASH);
    adrs.SetKeyPair(idx);
    unsigned char node[N];
    WotsPkFromSig(hash, sig, msg, adrs, node);
    adrs.SetTypeAndClear(AdrsType::TREE);
    adrs.SetTreeIndex(idx);
    ClimbTree(hash, adrs, idx, sig + LEN * N, HP, node);
    std::memcpy(root, node, N);
}

/** Algorithm 12, ht_sign: sign an n-byte message with the hypertree. */
void HtSign(const Hasher& hash, const unsigned char* msg, const unsigned char* sk_seed, uint64_t idx_tree, uint32_t idx_leaf, unsigned char* sig)
{
    Adrs adrs;
    adrs.SetTree(idx_tree);
    XmssSign(hash, msg, sk_seed, idx_leaf, adrs, sig);
    unsigned char root[N];
    XmssPkFromSig(hash, idx_leaf, sig, msg, adrs, root);
    for (unsigned j = 1; j < D; ++j) {
        idx_leaf = static_cast<uint32_t>(idx_tree & ((uint64_t{1} << HP) - 1));
        idx_tree >>= HP;
        adrs.SetLayer(j);
        adrs.SetTree(idx_tree);
        sig += XMSS_SIG_SIZE;
        XmssSign(hash, root, sk_seed, idx_leaf, adrs, sig);
        if (j < D - 1) XmssPkFromSig(hash, idx_leaf, sig, root, adrs, root);
    }
}

/** Algorithm 13, ht_verify: verify a hypertree signature of an n-byte message. */
bool HtVerify(const Hasher& hash, const unsigned char* msg, const unsigned char* sig, uint64_t idx_tree, uint32_t idx_leaf, const unsigned char* pk_root)
{
    Adrs adrs;
    adrs.SetTree(idx_tree);
    unsigned char node[N];
    XmssPkFromSig(hash, idx_leaf, sig, msg, adrs, node);
    for (unsigned j = 1; j < D; ++j) {
        idx_leaf = static_cast<uint32_t>(idx_tree & ((uint64_t{1} << HP) - 1));
        idx_tree >>= HP;
        adrs.SetLayer(j);
        adrs.SetTree(idx_tree);
        sig += XMSS_SIG_SIZE;
        XmssPkFromSig(hash, idx_leaf, sig, node, adrs, node);
    }
    return std::memcmp(node, pk_root, N) == 0;
}

/** Algorithm 4, base_2b with b = a: split the FORS message into k a-bit indices. */
void ForsIndices(const unsigned char* md, uint32_t indices[K])
{
    size_t in{0};
    unsigned bits{0};
    uint32_t total{0};
    for (unsigned out = 0; out < K; ++out) {
        while (bits < A) {
            total = (total << 8) | md[in++];
            bits += 8;
        }
        bits -= A;
        indices[out] = (total >> bits) & ((uint32_t{1} << A) - 1);
        total &= (uint32_t{1} << bits) - 1;
    }
    assert(in == MD_SIZE);
}

/** Algorithm 14, fors_skGen: derive a FORS secret value. */
void ForsSkGen(const Hasher& hash, const unsigned char* sk_seed, const Adrs& adrs, uint32_t idx, unsigned char* sk)
{
    Adrs sk_adrs{adrs};
    sk_adrs.SetTypeAndClear(AdrsType::FORS_PRF);
    sk_adrs.SetKeyPair(adrs.GetKeyPair());
    sk_adrs.SetTreeIndex(idx);
    Prf(hash, sk_adrs, sk_seed, sk);
}

/** Algorithm 15, fors_node: compute the node at height z and index i of the FORS trees. */
void ForsNode(const Hasher& hash, const unsigned char* sk_seed, uint32_t i, unsigned z, Adrs adrs, unsigned char* node)
{
    if (z == 0) {
        unsigned char sk[N];
        ForsSkGen(hash, sk_seed, adrs, i, sk);
        adrs.SetTreeHeight(0);
        adrs.SetTreeIndex(i);
        hash(adrs, sk, node);
        memory_cleanse(sk, sizeof(sk));
    } else {
        unsigned char children[2 * N];
        ForsNode(hash, sk_seed, 2 * i, z - 1, adrs, children);
        ForsNode(hash, sk_seed, 2 * i + 1, z - 1, adrs, children + N);
        adrs.SetTreeHeight(z);
        adrs.SetTreeIndex(i);
        hash(adrs, children, node);
    }
}

/** Algorithm 16, fors_sign: sign the FORS message md. For each of the k trees
 *  the signature holds one secret value and its authentication path. */
void ForsSign(const Hasher& hash, const unsigned char* md, const unsigned char* sk_seed, const Adrs& adrs, unsigned char* sig)
{
    uint32_t indices[K];
    ForsIndices(md, indices);
    for (unsigned i = 0; i < K; ++i) {
        ForsSkGen(hash, sk_seed, adrs, (i << A) + indices[i], sig);
        sig += N;
        for (unsigned j = 0; j < A; ++j) {
            const uint32_t s{(indices[i] >> j) ^ 1};
            ForsNode(hash, sk_seed, (i << (A - j)) + s, j, adrs, sig);
            sig += N;
        }
    }
}

/** Algorithm 17, fors_pkFromSig: compute the FORS public key from a signature. */
void ForsPkFromSig(const Hasher& hash, const unsigned char* sig, const unsigned char* md, Adrs adrs, unsigned char* pk)
{
    uint32_t indices[K];
    ForsIndices(md, indices);
    unsigned char roots[K * N];
    for (unsigned i = 0; i < K; ++i) {
        const unsigned char* sk{sig + i * (1 + A) * N};
        adrs.SetTreeHeight(0);
        adrs.SetTreeIndex((i << A) + indices[i]);
        unsigned char* node{roots + i * N};
        hash(adrs, std::span{sk, N}, node);
        ClimbTree(hash, adrs, indices[i], sk + N, A, node);
    }
    Adrs pk_adrs{adrs};
    pk_adrs.SetTypeAndClear(AdrsType::FORS_ROOTS);
    pk_adrs.SetKeyPair(adrs.GetKeyPair());
    hash(pk_adrs, roots, pk);
}

/** Algorithm 19, slh_sign_internal, for the message prefix || msg. */
void SignImpl(std::span<const unsigned char> prefix, std::span<const unsigned char> msg, std::span<const unsigned char, SECRET_KEY_SIZE> secret_key, std::span<const unsigned char> addrnd, std::span<unsigned char, SIGNATURE_SIZE> signature)
{
    assert(addrnd.empty() || addrnd.size() == N);
    const unsigned char* sk_seed{secret_key.data()};
    const unsigned char* sk_prf{secret_key.data() + N};
    const auto pk{secret_key.subspan<2 * N, PUBLIC_KEY_SIZE>()};
    const Hasher hash{pk.first<N>()};

    // The deterministic variant uses PK.seed in place of fresh randomness.
    const unsigned char* opt_rand{addrnd.empty() ? pk.data() : addrnd.data()};
    unsigned char* r{signature.data()};
    PrfMsg(sk_prf, opt_rand, prefix, msg, r);

    unsigned char digest[DIGEST_SIZE];
    HMsg(r, pk, prefix, msg, digest);
    uint64_t idx_tree;
    uint32_t idx_leaf;
    SplitDigest(digest, idx_tree, idx_leaf);

    Adrs adrs;
    adrs.SetTree(idx_tree);
    adrs.SetTypeAndClear(AdrsType::FORS_TREE);
    adrs.SetKeyPair(idx_leaf);
    unsigned char* sig_fors{r + N};
    ForsSign(hash, digest, sk_seed, adrs, sig_fors);
    unsigned char pk_fors[N];
    ForsPkFromSig(hash, sig_fors, digest, adrs, pk_fors);
    HtSign(hash, pk_fors, sk_seed, idx_tree, idx_leaf, sig_fors + FORS_SIG_SIZE);
}

/** Algorithm 20, slh_verify_internal, for the message prefix || msg. */
bool VerifyImpl(std::span<const unsigned char> prefix, std::span<const unsigned char> msg, std::span<const unsigned char> signature, std::span<const unsigned char, PUBLIC_KEY_SIZE> public_key)
{
    if (signature.size() != SIGNATURE_SIZE) return false;
    const Hasher hash{public_key.first<N>()};
    const unsigned char* r{signature.data()};
    const unsigned char* sig_fors{r + N};
    const unsigned char* sig_ht{sig_fors + FORS_SIG_SIZE};

    unsigned char digest[DIGEST_SIZE];
    HMsg(r, public_key, prefix, msg, digest);
    uint64_t idx_tree;
    uint32_t idx_leaf;
    SplitDigest(digest, idx_tree, idx_leaf);

    Adrs adrs;
    adrs.SetTree(idx_tree);
    adrs.SetTypeAndClear(AdrsType::FORS_TREE);
    adrs.SetKeyPair(idx_leaf);
    unsigned char pk_fors[N];
    ForsPkFromSig(hash, sig_fors, digest, adrs, pk_fors);
    return HtVerify(hash, pk_fors, sig_ht, idx_tree, idx_leaf, public_key.data() + N);
}

/** The message prefix of the "pure" external interface (FIPS 205 Algorithms
 *  22 and 24): toByte(0, 1) || toByte(|ctx|, 1) || ctx. */
class ContextPrefix
{
public:
    explicit ContextPrefix(std::span<const unsigned char> context) : m_size{2 + context.size()}
    {
        assert(context.size() <= MAX_CONTEXT_SIZE);
        m_data[0] = 0;
        m_data[1] = static_cast<unsigned char>(context.size());
        if (!context.empty()) std::memcpy(m_data + 2, context.data(), context.size());
    }
    std::span<const unsigned char> Get() const { return {m_data, m_size}; }

private:
    unsigned char m_data[2 + MAX_CONTEXT_SIZE];
    size_t m_size;
};

} // namespace

void KeyGen(std::span<const unsigned char, N> sk_seed,
            std::span<const unsigned char, N> sk_prf,
            std::span<const unsigned char, N> pk_seed,
            std::span<unsigned char, SECRET_KEY_SIZE> secret_key,
            std::span<unsigned char, PUBLIC_KEY_SIZE> public_key)
{
    // Algorithm 18, slh_keygen_internal. PK.root is the root of the single
    // XMSS tree in the top layer of the hypertree.
    const Hasher hash{pk_seed};
    Adrs adrs;
    adrs.SetLayer(D - 1);
    unsigned char pk_root[N];
    XmssNode(hash, sk_seed.data(), 0, HP, adrs, pk_root);

    std::memcpy(public_key.data(), pk_seed.data(), N);
    std::memcpy(public_key.data() + N, pk_root, N);
    std::memcpy(secret_key.data(), sk_seed.data(), N);
    std::memcpy(secret_key.data() + N, sk_prf.data(), N);
    std::memcpy(secret_key.data() + 2 * N, public_key.data(), PUBLIC_KEY_SIZE);
}

void SignInternal(std::span<const unsigned char> msg,
                  std::span<const unsigned char, SECRET_KEY_SIZE> secret_key,
                  std::span<const unsigned char> addrnd,
                  std::span<unsigned char, SIGNATURE_SIZE> signature)
{
    SignImpl({}, msg, secret_key, addrnd, signature);
}

bool VerifyInternal(std::span<const unsigned char> msg,
                    std::span<const unsigned char> signature,
                    std::span<const unsigned char, PUBLIC_KEY_SIZE> public_key)
{
    return VerifyImpl({}, msg, signature, public_key);
}

bool Sign(std::span<const unsigned char> msg,
          std::span<const unsigned char> context,
          std::span<const unsigned char, SECRET_KEY_SIZE> secret_key,
          std::span<const unsigned char> addrnd,
          std::span<unsigned char, SIGNATURE_SIZE> signature)
{
    if (context.size() > MAX_CONTEXT_SIZE) return false;
    const ContextPrefix prefix{context};
    SignImpl(prefix.Get(), msg, secret_key, addrnd, signature);
    return true;
}

bool Verify(std::span<const unsigned char> msg,
            std::span<const unsigned char> signature,
            std::span<const unsigned char> context,
            std::span<const unsigned char, PUBLIC_KEY_SIZE> public_key)
{
    if (context.size() > MAX_CONTEXT_SIZE) return false;
    const ContextPrefix prefix{context};
    return VerifyImpl(prefix.Get(), msg, signature, public_key);
}

} // namespace slhdsa
