// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <crypto/slhdsa.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/solver.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

constexpr script_verify_flags CONSENSUS_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR};

/** A P2MR output with two leaves, and a transaction that spends it through
 *  the first leaf: `<SLH-DSA public key> OP_CHECKSIG`. */
struct SlhDsaSpend {
    std::array<unsigned char, slhdsa::SECRET_KEY_SIZE> secret_key;
    std::array<unsigned char, slhdsa::PUBLIC_KEY_SIZE> public_key;
    CScript leaf_script;
    uint256 leaf_hash;
    valtype control_block;
    CTxOut prevout;
    CMutableTransaction tx;

    explicit SlhDsaSpend(FastRandomContext& rng)
    {
        const auto sk_seed{rng.randbytes<slhdsa::N, unsigned char>()};
        const auto sk_prf{rng.randbytes<slhdsa::N, unsigned char>()};
        const auto pk_seed{rng.randbytes<slhdsa::N, unsigned char>()};
        slhdsa::KeyGen(sk_seed, sk_prf, pk_seed, secret_key, public_key);

        valtype script_key{SLHDSA_PUBKEY_TYPE};
        script_key.insert(script_key.end(), public_key.begin(), public_key.end());
        leaf_script = CScript() << script_key << OP_CHECKSIG;
        leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_script);
        const uint256 sibling{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, CScript() << OP_TRUE)};
        const uint256 merkle_root{ComputeTapbranchHash(leaf_hash, sibling)};

        control_block = {TAPROOT_LEAF_TAPSCRIPT | 1};
        control_block.insert(control_block.end(), sibling.begin(), sibling.end());
        BOOST_CHECK(ComputeP2MRMerkleRoot(control_block, leaf_hash) == merkle_root);

        prevout = CTxOut{2 * CENT, CScript() << OP_2 << ToByteVector(merkle_root)};
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(rng.rand256()), 0});
        tx.vout.emplace_back(CENT, CScript() << OP_TRUE);
    }

    /** The BIP 342 signature hash for the spend. */
    uint256 SigHash(uint8_t hash_type) const
    {
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {prevout}, /*force=*/true);
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash = leaf_hash;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        execdata.m_codeseparator_pos_init = true;
        uint256 sighash;
        BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, tx, 0, hash_type, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));
        return sighash;
    }

    /** Sign the spend and set its witness. */
    void Sign(uint8_t hash_type = SIGHASH_DEFAULT)
    {
        const uint256 sighash{SigHash(hash_type)};
        std::array<unsigned char, slhdsa::SIGNATURE_SIZE> sig;
        BOOST_REQUIRE(slhdsa::Sign(std::span<const unsigned char>{sighash.data(), sighash.size()}, {}, secret_key, {}, sig));
        valtype sig_element{sig.begin(), sig.end()};
        if (hash_type != SIGHASH_DEFAULT) sig_element.push_back(hash_type);
        tx.vin[0].scriptWitness.stack = {sig_element, valtype{leaf_script.begin(), leaf_script.end()}, control_block};
    }

    ScriptError Verify(script_verify_flags flags) const
    {
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {prevout});
        ScriptError error;
        const bool ok{VerifyScript(CScript{}, prevout.scriptPubKey, &tx.vin[0].scriptWitness, flags,
                                   MutableTransactionSignatureChecker{&tx, 0, prevout.nValue, txdata, MissingDataBehavior::ASSERT_FAIL}, &error)};
        BOOST_CHECK_EQUAL(ok, error == SCRIPT_ERR_OK);
        return error;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2mr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(output_type)
{
    const CScript p2mr{CScript() << OP_2 << valtype(32, 0x42)};
    std::vector<valtype> solutions;
    BOOST_CHECK_EQUAL(Solver(p2mr, solutions), TxoutType::WITNESS_V2_P2MR);
    BOOST_REQUIRE_EQUAL(solutions.size(), 1U);
    BOOST_CHECK(solutions[0] == valtype(32, 0x42));
    BOOST_CHECK_EQUAL(GetTxnOutputType(TxoutType::WITNESS_V2_P2MR), "witness_v2_p2mr");
    TxoutType type;
    BOOST_CHECK(IsStandard(p2mr, type));
    BOOST_CHECK_EQUAL(type, TxoutType::WITNESS_V2_P2MR);

    // Witness v2 programs of another size, and other versions, are not P2MR.
    BOOST_CHECK_EQUAL(Solver(CScript() << OP_2 << valtype(20, 0x42), solutions), TxoutType::WITNESS_UNKNOWN);
    BOOST_CHECK_EQUAL(Solver(CScript() << OP_3 << valtype(32, 0x42), solutions), TxoutType::WITNESS_UNKNOWN);
}

BOOST_AUTO_TEST_CASE(slhdsa_spend)
{
    SlhDsaSpend spend{m_rng};
    spend.Sign();
    auto& stack{spend.tx.vin[0].scriptWitness.stack};
    BOOST_CHECK_EQUAL(stack[0].size(), SLHDSA_SIGNATURE_SIZE);

    // Valid under the consensus rules and under the standardness rules.
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(spend.Verify(STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_P2MR), SCRIPT_ERR_OK);

    // Without the P2MR flag the output is an unknown witness program: anyone
    // can spend it, and doing so is discouraged.
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS & ~SCRIPT_VERIFY_P2MR), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(spend.Verify(STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);

    // A damaged signature is only invalid when the P2MR rules apply.
    stack[0][m_rng.randrange(stack[0].size())] ^= 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS & ~SCRIPT_VERIFY_P2MR), SCRIPT_ERR_OK);
    spend.Sign();

    // The signature commits to the transaction.
    spend.tx.vout[0].nValue -= 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    spend.tx.vout[0].nValue += 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);

    // An explicit sighash type must not be the default, and must be defined.
    stack[0].push_back(SIGHASH_DEFAULT);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG_HASHTYPE);
    stack[0].back() = 0x04;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG_HASHTYPE);
    // A signature made for the default sighash type does not verify under another.
    stack[0].back() = SIGHASH_ALL;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    spend.Sign(SIGHASH_ALL);
    BOOST_CHECK_EQUAL(stack[0].size(), SLHDSA_SIGNATURE_SIZE + 1);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);

    // Elements larger than 520 bytes must have exactly the size of a signature.
    stack[0].push_back(0);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_PUSH_SIZE);
    stack[0].resize(SLHDSA_SIGNATURE_SIZE - 1);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_PUSH_SIZE);
    // An empty signature fails the check, but not the script.
    stack[0].clear();
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_EVAL_FALSE);
    spend.Sign();

    // The control block: its size, its lowest bit, and the Merkle path.
    stack[2].push_back(0);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
    stack[2].clear();
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_P2MR_WRONG_CONTROL_SIZE);
    stack[2] = spend.control_block;
    stack[2][0] &= 0xfe;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_P2MR_WRONG_CONTROL_BYTE);
    stack[2] = spend.control_block;
    stack[2].back() ^= 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    stack[2] = spend.control_block;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);

    // A witness needs a script and a control block.
    const auto full_stack{stack};
    stack = {full_stack[2]};
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    stack.clear();
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

BOOST_AUTO_TEST_CASE(slhdsa_signature_cache)
{
    SlhDsaSpend spend{m_rng};
    spend.Sign();
    const CTransaction tx{spend.tx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, {spend.prevout});
    SignatureCache cache{DEFAULT_SIGNATURE_CACHE_BYTES};

    uint256 entry;
    const uint256 sighash{spend.SigHash(SIGHASH_DEFAULT)};
    cache.ComputeEntrySLHDSA(entry, sighash, tx.vin[0].scriptWitness.stack[0], spend.public_key);

    // A check that does not store leaves the cache empty.
    BOOST_CHECK(VerifyScript(CScript{}, spend.prevout.scriptPubKey, &tx.vin[0].scriptWitness, CONSENSUS_FLAGS,
                             CachingTransactionSignatureChecker{&tx, 0, spend.prevout.nValue, /*storeIn=*/false, cache, txdata}));
    BOOST_CHECK(!cache.Get(entry, /*erase=*/false));
    // A check that stores adds the entry, under which the signature is then found.
    BOOST_CHECK(VerifyScript(CScript{}, spend.prevout.scriptPubKey, &tx.vin[0].scriptWitness, CONSENSUS_FLAGS,
                             CachingTransactionSignatureChecker{&tx, 0, spend.prevout.nValue, /*storeIn=*/true, cache, txdata}));
    BOOST_CHECK(cache.Get(entry, /*erase=*/false));
    BOOST_CHECK(VerifyScript(CScript{}, spend.prevout.scriptPubKey, &tx.vin[0].scriptWitness, CONSENSUS_FLAGS,
                             CachingTransactionSignatureChecker{&tx, 0, spend.prevout.nValue, /*storeIn=*/true, cache, txdata}));

    // The entry is specific to the signature, the message and the key.
    uint256 other;
    valtype damaged{tx.vin[0].scriptWitness.stack[0]};
    damaged[0] ^= 1;
    cache.ComputeEntrySLHDSA(other, sighash, damaged, spend.public_key);
    BOOST_CHECK(other != entry);
    BOOST_CHECK(!cache.Get(other, /*erase=*/false));
    cache.ComputeEntrySLHDSA(other, spend.SigHash(SIGHASH_ALL), tx.vin[0].scriptWitness.stack[0], spend.public_key);
    BOOST_CHECK(other != entry);
    // It does not collide with a Schnorr entry for the same data.
    cache.ComputeEntrySchnorr(other, sighash, tx.vin[0].scriptWitness.stack[0], XOnlyPubKey{spend.public_key});
    BOOST_CHECK(other != entry);
}

BOOST_AUTO_TEST_SUITE_END()
