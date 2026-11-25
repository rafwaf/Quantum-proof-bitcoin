// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/slhdsa.h>
#include <deploymentinfo.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <serialize.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace {

using valtype = std::vector<unsigned char>;

constexpr script_verify_flags CONSENSUS_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR};

/** An SLH-DSA key pair. */
struct SlhDsaKey {
    std::array<unsigned char, slhdsa::SECRET_KEY_SIZE> secret;
    std::array<unsigned char, slhdsa::PUBLIC_KEY_SIZE> pub;

    explicit SlhDsaKey(FastRandomContext& rng)
    {
        const auto sk_seed{rng.randbytes<slhdsa::N, unsigned char>()};
        const auto sk_prf{rng.randbytes<slhdsa::N, unsigned char>()};
        const auto pk_seed{rng.randbytes<slhdsa::N, unsigned char>()};
        slhdsa::KeyGen(sk_seed, sk_prf, pk_seed, secret, pub);
    }

    /** The public key in the form it takes in a P2MR leaf script. */
    valtype ScriptKey() const
    {
        valtype key{SLHDSA_PUBKEY_TYPE};
        key.insert(key.end(), pub.begin(), pub.end());
        return key;
    }
};

/** A P2MR output with two leaves, and a transaction that spends it through
 *  the first leaf, which holds the given script. */
struct P2MRSpend {
    CScript leaf_script;
    uint256 leaf_hash;
    valtype control_block;
    CTxOut prevout;
    CMutableTransaction tx;

    P2MRSpend(const CScript& script, FastRandomContext& rng) : leaf_script{script}
    {
        leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf_script);
        const uint256 sibling{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, CScript() << OP_RETURN)};
        const uint256 merkle_root{ComputeTapbranchHash(leaf_hash, sibling)};

        control_block = {TAPROOT_LEAF_TAPSCRIPT | 1};
        control_block.insert(control_block.end(), sibling.begin(), sibling.end());
        BOOST_CHECK(ComputeP2MRMerkleRoot(control_block, leaf_hash) == merkle_root);

        prevout = CTxOut{2 * CENT, CScript() << OP_2 << ToByteVector(merkle_root)};
        tx.vin.emplace_back(COutPoint{Txid::FromUint256(rng.rand256()), 0});
        tx.vout.emplace_back(CENT, CScript() << OP_TRUE);
        SetStack({});
    }

    /** Set the witness: the given initial stack, the script and the control block. */
    void SetStack(std::vector<valtype> stack)
    {
        stack.emplace_back(leaf_script.begin(), leaf_script.end());
        stack.push_back(control_block);
        tx.vin[0].scriptWitness.stack = std::move(stack);
    }

    /** The BIP 342 signature hash of the spend. */
    uint256 SigHash(uint8_t hash_type = SIGHASH_DEFAULT) const
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

    /** An SLH-DSA signature of the spend, as a witness stack element. */
    valtype Sign(const SlhDsaKey& key, uint8_t hash_type = SIGHASH_DEFAULT) const
    {
        const uint256 sighash{SigHash(hash_type)};
        std::array<unsigned char, slhdsa::SIGNATURE_SIZE> sig;
        BOOST_REQUIRE(slhdsa::Sign(std::span<const unsigned char>{sighash.data(), sighash.size()}, {}, key.secret, {}, sig));
        valtype element{sig.begin(), sig.end()};
        if (hash_type != SIGHASH_DEFAULT) element.push_back(hash_type);
        return element;
    }

    /** The validation weight budget of the spend (BIP 342). */
    int64_t Budget() const
    {
        return VALIDATION_WEIGHT_OFFSET + int64_t(::GetSerializeSize(tx.vin[0].scriptWitness.stack));
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

/** A leaf script that checks one SLH-DSA signature. */
CScript SingleSigScript(const SlhDsaKey& key)
{
    return CScript() << key.ScriptKey() << OP_CHECKSIG;
}

/** Make a random combination of script flags one that VerifyScript accepts. */
script_verify_flags NormalizeFlags(script_verify_flags flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    if (flags & (SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR)) flags |= SCRIPT_VERIFY_WITNESS;
    if (flags & SCRIPT_VERIFY_WITNESS) flags |= SCRIPT_VERIFY_P2SH;
    return flags;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(p2mr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(activation_parameters)
{
    // P2MR has no activation height on the Bitcoin networks. A node follows
    // Bitcoin's consensus rules there until the fork is given a height.
    const ArgsManager args;
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET}) {
        const auto params{CreateChainParams(args, chain)};
        BOOST_CHECK_EQUAL(params->GetConsensus().P2MRHeight, std::numeric_limits<int>::max());
        BOOST_CHECK_EQUAL(params->GetConsensus().DeploymentHeight(Consensus::DEPLOYMENT_P2MR), std::numeric_limits<int>::max());
    }
    // On regtest it is active from the first block, unless overridden.
    BOOST_CHECK_EQUAL(CreateChainParams(args, ChainType::REGTEST)->GetConsensus().P2MRHeight, 0);

    BOOST_CHECK_EQUAL(DeploymentName(Consensus::DEPLOYMENT_P2MR), "p2mr");
    BOOST_CHECK(GetBuriedDeployment("p2mr") == Consensus::DEPLOYMENT_P2MR);
}

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
    const SlhDsaKey key{m_rng};
    P2MRSpend spend{SingleSigScript(key), m_rng};
    spend.SetStack({spend.Sign(key)});
    auto& stack{spend.tx.vin[0].scriptWitness.stack};
    BOOST_CHECK_EQUAL(stack[0].size(), SLHDSA_SIGNATURE_SIZE);

    // Valid under the consensus rules and under the standardness rules, which include P2MR.
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
    BOOST_CHECK(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_P2MR);
    BOOST_CHECK_EQUAL(spend.Verify(STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_OK);

    // A damaged signature is only invalid when the P2MR rules apply. Without
    // the flag any witness spends the output, as for Taproot without its flag.
    stack[0][m_rng.randrange(stack[0].size())] ^= 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    BOOST_CHECK_EQUAL(spend.Verify(STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS & ~SCRIPT_VERIFY_P2MR), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(spend.Verify(STANDARD_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_P2MR), SCRIPT_ERR_OK);
    spend.SetStack({spend.Sign(key)});

    // The signature commits to the transaction.
    spend.tx.vout[0].nValue -= 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    spend.tx.vout[0].nValue += 1;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);

    // A signature of another key does not verify.
    const SlhDsaKey other_key{m_rng};
    spend.SetStack({spend.Sign(other_key)});
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    spend.SetStack({spend.Sign(key)});

    // An explicit sighash type must not be the default, and must be defined.
    stack[0].push_back(SIGHASH_DEFAULT);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG_HASHTYPE);
    stack[0].back() = 0x04;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG_HASHTYPE);
    // A signature made for the default sighash type does not verify under another.
    stack[0].back() = SIGHASH_ALL;
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG);
    spend.SetStack({spend.Sign(key, SIGHASH_ALL)});
    BOOST_CHECK_EQUAL(stack[0].size(), SLHDSA_SIGNATURE_SIZE + 1);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);

    // Elements larger than 520 bytes must have exactly the size of a signature.
    stack[0].push_back(0);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_PUSH_SIZE);
    stack[0].resize(SLHDSA_SIGNATURE_SIZE - 1);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_PUSH_SIZE);
    stack[0].resize(MAX_SCRIPT_ELEMENT_SIZE + 1);
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_PUSH_SIZE);
    // An empty signature fails the check, but not the script.
    stack[0].clear();
    BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_EVAL_FALSE);
    spend.SetStack({spend.Sign(key)});

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

BOOST_AUTO_TEST_CASE(flag_only_restricts)
{
    // Script verification flags are soft forks: anything valid with a flag set
    // is valid without it. Check that for SCRIPT_VERIFY_P2MR, with valid and
    // invalid spends and under random combinations of the other flags.
    const SlhDsaKey key{m_rng};
    P2MRSpend valid{SingleSigScript(key), m_rng};
    valid.SetStack({valid.Sign(key)});
    P2MRSpend damaged{valid};
    damaged.tx.vin[0].scriptWitness.stack[0][0] ^= 1;
    P2MRSpend garbage{valid};
    garbage.tx.vin[0].scriptWitness.stack = {{0x01}};
    P2MRSpend no_witness{valid};
    no_witness.tx.vin[0].scriptWitness.stack.clear();
    P2MRSpend trivial{CScript() << OP_TRUE, m_rng};

    size_t valid_with_flag{0}, valid_only_without_flag{0};
    for (int i = 0; i < 300; ++i) {
        const script_verify_flags flags{NormalizeFlags(script_verify_flags::from_int(m_rng.randrange(MAX_SCRIPT_VERIFY_FLAGS)))};
        const script_verify_flags with{NormalizeFlags(flags | SCRIPT_VERIFY_P2MR)};
        const script_verify_flags without{with & ~SCRIPT_VERIFY_P2MR};
        for (const P2MRSpend* spend : {&valid, &damaged, &garbage, &no_witness, &trivial}) {
            const bool ok_with{spend->Verify(with) == SCRIPT_ERR_OK};
            const bool ok_without{spend->Verify(without) == SCRIPT_ERR_OK};
            BOOST_CHECK(!ok_with || ok_without);
            valid_with_flag += ok_with;
            valid_only_without_flag += !ok_with && ok_without;
        }
    }
    // Make sure both situations occurred.
    BOOST_CHECK(valid_with_flag > 0);
    BOOST_CHECK(valid_only_without_flag > 0);
}

BOOST_AUTO_TEST_CASE(validation_weight)
{
    // A check of a non-empty signature costs 1000 units of validation weight
    // for an SLH-DSA key and 50 for any other key, out of a budget of 50 plus
    // the size of the witness. Find the exact point at which the budget runs
    // out, with a script that checks one valid SLH-DSA signature and then a
    // number of signatures of keys of an unknown type, which always pass.
    const SlhDsaKey key{m_rng};
    const valtype unknown_key{0x99, 0x99};
    const auto build{[&](int unknown_checks, size_t padding, bool sign) {
        CScript script;
        script << OP_DROP << key.ScriptKey() << OP_CHECKSIGVERIFY;
        for (int i = 0; i < unknown_checks; ++i) script << unknown_key << OP_CHECKSIGVERIFY;
        script << OP_TRUE;
        P2MRSpend spend{script, m_rng};
        std::vector<valtype> stack(unknown_checks, valtype{0x01});
        // The budget depends on the size of the signature only.
        stack.push_back(sign ? spend.Sign(key) : valtype(SLHDSA_SIGNATURE_SIZE));
        stack.emplace_back(padding, 0x00);
        spend.SetStack(stack);
        return spend;
    }};
    const auto cost{[](int unknown_checks) {
        return VALIDATION_WEIGHT_PER_SLHDSA_SIGOP_PASSED + unknown_checks * VALIDATION_WEIGHT_PER_SIGOP_PASSED;
    }};

    // Each further check adds less to the budget than it costs. Find the number
    // of checks for which a few bytes of padding make the budget exact.
    std::optional<std::pair<int, size_t>> exact;
    for (int checks = 100; checks < 250 && !exact; ++checks) {
        const int64_t shortfall{cost(checks) - build(checks, 0, /*sign=*/false).Budget()};
        if (shortfall >= 1 && shortfall <= 60) exact = {checks, size_t(shortfall)};
    }
    BOOST_REQUIRE(exact.has_value());
    const auto [checks, padding]{*exact};

    const P2MRSpend within{build(checks, padding, /*sign=*/true)};
    BOOST_CHECK_EQUAL(within.Budget(), cost(checks));
    BOOST_CHECK_EQUAL(within.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
    const P2MRSpend beyond{build(checks, padding - 1, /*sign=*/true)};
    BOOST_CHECK_EQUAL(beyond.Budget(), cost(checks) - 1);
    BOOST_CHECK_EQUAL(beyond.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);

    // A signature that is too short cannot pay for the check of an SLH-DSA
    // key. With a budget of exactly 1000 the check is paid for, and then
    // fails on the size of the signature.
    const CScript padded_script{CScript() << OP_2DROP << key.ScriptKey() << OP_CHECKSIG};
    P2MRSpend short_sig{padded_script, m_rng};
    short_sig.SetStack({{0x01}});
    BOOST_CHECK_EQUAL(short_sig.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_INVALID_STACK_OPERATION);
    short_sig.SetStack({{0x01}, valtype(MAX_SCRIPT_ELEMENT_SIZE), valtype{}});
    const int64_t missing{VALIDATION_WEIGHT_PER_SLHDSA_SIGOP_PASSED - short_sig.Budget()};
    BOOST_REQUIRE(missing > 3 && missing <= int64_t{MAX_SCRIPT_ELEMENT_SIZE});
    // An element of 253 bytes or more has a 3-byte length prefix instead of 1.
    const size_t last_padding{size_t(missing) - (missing >= 255 ? 2 : 0)};
    short_sig.SetStack({{0x01}, valtype(MAX_SCRIPT_ELEMENT_SIZE), valtype(last_padding)});
    BOOST_CHECK_EQUAL(short_sig.Budget(), VALIDATION_WEIGHT_PER_SLHDSA_SIGOP_PASSED);
    BOOST_CHECK_EQUAL(short_sig.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SLHDSA_SIG_SIZE);
    short_sig.SetStack({{0x01}, valtype(MAX_SCRIPT_ELEMENT_SIZE), valtype(last_padding - 1)});
    BOOST_CHECK_EQUAL(short_sig.Budget(), VALIDATION_WEIGHT_PER_SLHDSA_SIGOP_PASSED - 1);
    BOOST_CHECK_EQUAL(short_sig.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
}

BOOST_AUTO_TEST_CASE(oversized_elements)
{
    // A P2MR witness stack may hold elements with the size of an SLH-DSA
    // signature. Scripts may move, measure, compare and drop such an element,
    // but not copy or hash it.
    struct Case {
        std::string name;
        CScript script;
        //! Initial stack, bottom first: true for the element under test, false for a small element.
        std::vector<bool> stack;
        //! Whether the script must fail when the element under test is oversized.
        bool refused;
    };
    const valtype size_as_number{CScriptNum{SLHDSA_SIGNATURE_SIZE}.getvch()};
    const std::vector<Case> cases{
        // Opcodes that copy the element under test.
        {"TOALTSTACK", CScript() << OP_TOALTSTACK << OP_FROMALTSTACK << OP_DROP << OP_TRUE, {true}, true},
        {"2DUP first", CScript() << OP_2DUP << OP_2DROP << OP_2DROP << OP_TRUE, {true, false}, true},
        {"2DUP second", CScript() << OP_2DUP << OP_2DROP << OP_2DROP << OP_TRUE, {false, true}, true},
        {"3DUP first", CScript() << OP_3DUP << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {true, false, false}, true},
        {"3DUP second", CScript() << OP_3DUP << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, true, false}, true},
        {"3DUP third", CScript() << OP_3DUP << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, false, true}, true},
        {"2OVER first", CScript() << OP_2OVER << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {true, false, false, false}, true},
        {"2OVER second", CScript() << OP_2OVER << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, true, false, false}, true},
        {"2ROT first", CScript() << OP_2ROT << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {true, false, false, false, false, false}, true},
        {"2ROT second", CScript() << OP_2ROT << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, true, false, false, false, false}, true},
        {"IFDUP", CScript() << OP_IFDUP << OP_2DROP << OP_TRUE, {true}, true},
        {"DUP", CScript() << OP_DUP << OP_2DROP << OP_TRUE, {true}, true},
        {"OVER", CScript() << OP_OVER << OP_2DROP << OP_DROP << OP_TRUE, {true, false}, true},
        {"PICK", CScript() << OP_1 << OP_PICK << OP_2DROP << OP_DROP << OP_TRUE, {true, false}, true},
        {"ROLL", CScript() << OP_1 << OP_ROLL << OP_2DROP << OP_TRUE, {true, false}, true},
        {"TUCK", CScript() << OP_TUCK << OP_2DROP << OP_DROP << OP_TRUE, {false, true}, true},
        // Opcodes that hash it.
        {"RIPEMD160", CScript() << OP_RIPEMD160 << OP_DROP << OP_TRUE, {true}, true},
        {"SHA1", CScript() << OP_SHA1 << OP_DROP << OP_TRUE, {true}, true},
        {"SHA256", CScript() << OP_SHA256 << OP_DROP << OP_TRUE, {true}, true},
        {"HASH160", CScript() << OP_HASH160 << OP_DROP << OP_TRUE, {true}, true},
        {"HASH256", CScript() << OP_HASH256 << OP_DROP << OP_TRUE, {true}, true},
        // The same opcodes when they copy other elements than the one under test.
        {"2OVER third", CScript() << OP_2OVER << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, false, true, false}, false},
        {"2OVER fourth", CScript() << OP_2OVER << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, false, false, true}, false},
        {"2ROT third", CScript() << OP_2ROT << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, false, true, false, false, false}, false},
        {"2ROT sixth", CScript() << OP_2ROT << OP_2DROP << OP_2DROP << OP_2DROP << OP_TRUE, {false, false, false, false, false, true}, false},
        {"OVER top", CScript() << OP_OVER << OP_2DROP << OP_DROP << OP_TRUE, {false, true}, false},
        {"PICK other", CScript() << OP_0 << OP_PICK << OP_2DROP << OP_DROP << OP_TRUE, {true, false}, false},
        {"ROLL other", CScript() << OP_0 << OP_ROLL << OP_2DROP << OP_TRUE, {true, false}, false},
        {"TUCK below", CScript() << OP_TUCK << OP_2DROP << OP_DROP << OP_TRUE, {true, false}, false},
        // Opcodes that move, measure, compare or drop it.
        {"SWAP", CScript() << OP_SWAP << OP_2DROP << OP_TRUE, {true, false}, false},
        {"ROT", CScript() << OP_ROT << OP_2DROP << OP_DROP << OP_TRUE, {true, false, false}, false},
        {"2SWAP", CScript() << OP_2SWAP << OP_2DROP << OP_2DROP << OP_TRUE, {true, true, false, false}, false},
        {"NIP", CScript() << OP_NIP << OP_DROP << OP_TRUE, {true, false}, false},
        {"DROP", CScript() << OP_DROP << OP_TRUE, {true}, false},
        {"2DROP", CScript() << OP_2DROP << OP_TRUE, {true, true}, false},
        {"DEPTH", CScript() << OP_DEPTH << OP_2DROP << OP_TRUE, {true}, false},
        {"VERIFY", CScript() << OP_VERIFY << OP_TRUE, {true}, false},
        {"EQUAL", CScript() << OP_EQUAL, {true, true}, false},
        {"EQUALVERIFY", CScript() << OP_EQUALVERIFY << OP_TRUE, {true, true}, false},
        {"left as result", CScript{}, {true}, false},
    };

    const valtype small_element(8, 0x42);
    for (const Case& test : cases) {
        for (const size_t size : {size_t{MAX_SCRIPT_ELEMENT_SIZE}, size_t{SLHDSA_SIGNATURE_SIZE}, size_t{SLHDSA_SIGNATURE_SIZE + 1}}) {
            BOOST_TEST_CONTEXT(test.name << " with an element of " << size << " bytes")
            {
                P2MRSpend spend{test.script, m_rng};
                std::vector<valtype> stack;
                for (const bool under_test : test.stack) stack.push_back(under_test ? valtype(size, 0x42) : small_element);
                spend.SetStack(stack);
                const bool oversized{size > MAX_SCRIPT_ELEMENT_SIZE};
                BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), oversized && test.refused ? SCRIPT_ERR_PUSH_SIZE : SCRIPT_ERR_OK);
            }
        }
    }

    // OP_SIZE reports the size of an oversized element.
    P2MRSpend size_spend{CScript() << OP_SIZE << size_as_number << OP_EQUALVERIFY << OP_DROP << OP_TRUE, m_rng};
    size_spend.SetStack({valtype(SLHDSA_SIGNATURE_SIZE, 0x42)});
    BOOST_CHECK_EQUAL(size_spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
    size_spend.SetStack({valtype(SLHDSA_SIGNATURE_SIZE + 1, 0x42)});
    BOOST_CHECK_EQUAL(size_spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_EQUALVERIFY);

    // A signature can be moved to where it is needed and then checked, but a
    // copy of it cannot be made to check it twice.
    const SlhDsaKey key{m_rng};
    P2MRSpend moved{CScript() << OP_SWAP << key.ScriptKey() << OP_CHECKSIG << OP_NIP, m_rng};
    moved.SetStack({moved.Sign(key), small_element});
    BOOST_CHECK_EQUAL(moved.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
    P2MRSpend copied{CScript() << OP_DUP << key.ScriptKey() << OP_CHECKSIGVERIFY << key.ScriptKey() << OP_CHECKSIG, m_rng};
    copied.SetStack({copied.Sign(key)});
    BOOST_CHECK_EQUAL(copied.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(other_key_types)
{
    // In a P2MR script only a 33-byte key that starts with 0x80 is an SLH-DSA
    // key. Other keys keep their BIP 342 meaning: 32 bytes is a BIP 340 key,
    // an empty key fails, and anything else is of an unknown type, whose
    // checks pass for use by future rules and are discouraged until then.
    const SlhDsaKey key{m_rng};
    valtype wrong_type{key.ScriptKey()};
    wrong_type[0] = SLHDSA_PUBKEY_TYPE + 1;
    valtype too_long{key.ScriptKey()};
    too_long.push_back(0);
    valtype too_short{key.ScriptKey()};
    too_short.pop_back();
    BOOST_REQUIRE_EQUAL(too_short.size(), 32U);

    for (const valtype& unknown : {wrong_type, too_long, valtype{0x02, 0x02}}) {
        P2MRSpend spend{CScript() << unknown << OP_CHECKSIG, m_rng};
        spend.SetStack({{0x01}});
        BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(spend.Verify(STANDARD_SCRIPT_VERIFY_FLAGS), SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
        // An element with the size of an SLH-DSA signature is accepted as the signature too.
        spend.SetStack({valtype(SLHDSA_SIGNATURE_SIZE, 0x42)});
        BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_OK);
        spend.SetStack({valtype{}});
        BOOST_CHECK_EQUAL(spend.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_EVAL_FALSE);
    }

    // A 32-byte key is a BIP 340 key, which a signature of SLH-DSA size does not fit.
    P2MRSpend schnorr{CScript() << too_short << OP_CHECKSIG, m_rng};
    schnorr.SetStack({valtype(SLHDSA_SIGNATURE_SIZE, 0x42)});
    BOOST_CHECK_EQUAL(schnorr.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_SCHNORR_SIG_SIZE);

    P2MRSpend empty{CScript() << OP_0 << OP_CHECKSIG, m_rng};
    empty.SetStack({{0x01}});
    BOOST_CHECK_EQUAL(empty.Verify(CONSENSUS_FLAGS), SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);

    // In a Taproot script an SLH-DSA key is of an unknown type as well, and an
    // element of signature size is not allowed on the witness stack.
    const CScript script{SingleSigScript(key)};
    const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, script)};
    const XOnlyPubKey internal_key{XOnlyPubKey::NUMS_H};
    const auto tweaked{internal_key.CreateTapTweak(&leaf_hash)};
    BOOST_REQUIRE(tweaked.has_value());
    valtype control{static_cast<unsigned char>(TAPROOT_LEAF_TAPSCRIPT | (tweaked->second ? 1 : 0))};
    control.insert(control.end(), internal_key.begin(), internal_key.end());
    const CTxOut prevout{2 * CENT, CScript() << OP_1 << ToByteVector(tweaked->first)};
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(m_rng.rand256()), 0});
    tx.vout.emplace_back(CENT, CScript() << OP_TRUE);
    const auto verify_taproot{[&](const valtype& sig) {
        tx.vin[0].scriptWitness.stack = {sig, valtype{script.begin(), script.end()}, control};
        PrecomputedTransactionData txdata;
        txdata.Init(tx, {prevout});
        ScriptError error;
        VerifyScript(CScript{}, prevout.scriptPubKey, &tx.vin[0].scriptWitness, CONSENSUS_FLAGS,
                     MutableTransactionSignatureChecker{&tx, 0, prevout.nValue, txdata, MissingDataBehavior::ASSERT_FAIL}, &error);
        return error;
    }};
    BOOST_CHECK_EQUAL(verify_taproot({0x01}), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(verify_taproot(valtype(SLHDSA_SIGNATURE_SIZE, 0x42)), SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(p2sh_wrapped_is_not_p2mr)
{
    // A witness v2 program inside P2SH is not a P2MR output. It stays an
    // undefined witness program that any witness spends.
    const SlhDsaKey key{m_rng};
    P2MRSpend spend{SingleSigScript(key), m_rng};
    const CScript redeem_script{spend.prevout.scriptPubKey};
    const CScript script_pubkey{GetScriptForDestination(ScriptHash(redeem_script))};
    const CScript script_sig{CScript() << ToByteVector(redeem_script)};
    spend.tx.vin[0].scriptWitness.stack = {{0x01}};

    PrecomputedTransactionData txdata;
    txdata.Init(spend.tx, {CTxOut{spend.prevout.nValue, script_pubkey}});
    const MutableTransactionSignatureChecker checker{&spend.tx, 0, spend.prevout.nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
    ScriptError error;
    BOOST_CHECK(VerifyScript(script_sig, script_pubkey, &spend.tx.vin[0].scriptWitness, CONSENSUS_FLAGS, checker, &error));
    BOOST_CHECK(!VerifyScript(script_sig, script_pubkey, &spend.tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}

BOOST_AUTO_TEST_CASE(precomputed_transaction_data)
{
    // The data for BIP 341 signature hashes must be prepared for transactions
    // that spend P2MR outputs, wherever the P2MR input is among the inputs.
    const CTxOut p2mr{CENT, CScript() << OP_2 << valtype(32, 0x42)};
    const CTxOut p2wpkh{CENT, CScript() << OP_0 << valtype(20, 0x42)};
    const CTxOut p2pkh{CENT, GetScriptForDestination(PKHash{uint160{}})};

    const auto init{[&](const std::vector<CTxOut>& spent, const std::vector<bool>& has_witness) {
        CMutableTransaction tx;
        for (size_t i = 0; i < spent.size(); ++i) {
            tx.vin.emplace_back(COutPoint{Txid::FromUint256(m_rng.rand256()), 0});
            if (has_witness[i]) tx.vin.back().scriptWitness.stack = {{0x01}};
        }
        tx.vout.emplace_back(CENT, CScript() << OP_TRUE);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{spent});
        return txdata;
    }};

    BOOST_CHECK(init({p2mr}, {true}).m_bip341_taproot_ready);
    BOOST_CHECK(!init({p2mr}, {true}).m_bip143_segwit_ready);
    for (const auto& spent : {std::vector<CTxOut>{p2mr, p2wpkh}, std::vector<CTxOut>{p2wpkh, p2mr}}) {
        const auto txdata{init(spent, {true, true})};
        BOOST_CHECK(txdata.m_bip341_taproot_ready);
        BOOST_CHECK(txdata.m_bip143_segwit_ready);
    }
    BOOST_CHECK(init({p2pkh, p2pkh, p2mr}, {false, false, true}).m_bip341_taproot_ready);
    BOOST_CHECK(init({p2wpkh, p2wpkh}, {true, true}).m_bip143_segwit_ready);
    BOOST_CHECK(!init({p2wpkh, p2wpkh}, {true, true}).m_bip341_taproot_ready);
    // An input without a witness cannot be a valid P2MR spend, and is not prepared for.
    BOOST_CHECK(!init({p2mr}, {false}).m_bip341_taproot_ready);
}

BOOST_AUTO_TEST_CASE(standardness_before_activation)
{
    // Until the P2MR rules are active a P2MR output is an undefined witness
    // program, and spending one is not standard.
    const SlhDsaKey key{m_rng};
    P2MRSpend spend{SingleSigScript(key), m_rng};
    spend.SetStack({spend.Sign(key)});

    CMutableTransaction funding;
    funding.vout.push_back(spend.prevout);
    spend.tx.vin[0].prevout = COutPoint{funding.GetHash(), 0};
    CCoinsViewCache coins{&CoinsViewEmpty::Get()};
    AddCoins(coins, CTransaction{funding}, 0);

    const CTransaction tx{spend.tx};
    BOOST_CHECK(ValidateInputsStandardness(tx, coins, /*p2mr_active=*/true).IsValid());
    BOOST_CHECK(ValidateInputsStandardness(tx, coins).IsValid());
    const TxValidationState state{ValidateInputsStandardness(tx, coins, /*p2mr_active=*/false)};
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetResult(), TxValidationResult::TX_INPUTS_NOT_STANDARD);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonstandard-inputs");
    BOOST_CHECK_EQUAL(state.GetDebugMessage(), "input 0 witness program is undefined");
    BOOST_CHECK(IsWitnessStandard(tx, coins));
}

BOOST_AUTO_TEST_CASE(signing_keeps_witness)
{
    // The wallet cannot sign for P2MR outputs yet. Signing a transaction must
    // leave the witness of a P2MR input as it is, and report whether it is valid.
    const SlhDsaKey key{m_rng};
    P2MRSpend spend{SingleSigScript(key), m_rng};
    spend.SetStack({spend.Sign(key)});
    const std::vector<valtype> witness{spend.tx.vin[0].scriptWitness.stack};

    const FlatSigningProvider keystore;
    const std::map<COutPoint, Coin> coins{{spend.tx.vin[0].prevout, Coin{spend.prevout, /*nHeightIn=*/1, /*fCoinBaseIn=*/false}}};
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(spend.tx, &keystore, coins, {.sighash_type = SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(input_errors.empty());
    BOOST_CHECK(spend.tx.vin[0].scriptWitness.stack == witness);

    // An invalid witness is kept as well, and reported.
    spend.tx.vin[0].scriptWitness.stack[0][0] ^= 1;
    const std::vector<valtype> damaged{spend.tx.vin[0].scriptWitness.stack};
    BOOST_CHECK(!SignTransaction(spend.tx, &keystore, coins, {.sighash_type = SIGHASH_DEFAULT}, input_errors));
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1U);
    BOOST_CHECK_EQUAL(input_errors.at(0).original, ScriptErrorString(SCRIPT_ERR_SLHDSA_SIG));
    BOOST_CHECK(spend.tx.vin[0].scriptWitness.stack == damaged);
}

BOOST_AUTO_TEST_CASE(slhdsa_signature_cache)
{
    const SlhDsaKey key{m_rng};
    P2MRSpend spend{SingleSigScript(key), m_rng};
    spend.SetStack({spend.Sign(key)});
    const CTransaction tx{spend.tx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, {spend.prevout});
    SignatureCache cache{DEFAULT_SIGNATURE_CACHE_BYTES};
    const auto verify{[&](const CTransaction& tx_to, bool store) {
        return VerifyScript(CScript{}, spend.prevout.scriptPubKey, &tx_to.vin[0].scriptWitness, CONSENSUS_FLAGS,
                            CachingTransactionSignatureChecker{&tx_to, 0, spend.prevout.nValue, store, cache, txdata});
    }};

    uint256 entry;
    const uint256 sighash{spend.SigHash()};
    cache.ComputeEntrySLHDSA(entry, sighash, tx.vin[0].scriptWitness.stack[0], key.pub);

    // A check that does not store leaves the cache empty.
    BOOST_CHECK(verify(tx, /*store=*/false));
    BOOST_CHECK(!cache.Get(entry, /*erase=*/false));
    // A check that stores adds the entry.
    BOOST_CHECK(verify(tx, /*store=*/true));
    BOOST_CHECK(cache.Get(entry, /*erase=*/false));

    // The entry is specific to the signature, the message and the key.
    uint256 other;
    valtype damaged_sig{tx.vin[0].scriptWitness.stack[0]};
    damaged_sig[0] ^= 1;
    cache.ComputeEntrySLHDSA(other, sighash, damaged_sig, key.pub);
    BOOST_CHECK(other != entry);
    BOOST_CHECK(!cache.Get(other, /*erase=*/false));
    uint256 another;
    cache.ComputeEntrySLHDSA(another, spend.SigHash(SIGHASH_ALL), tx.vin[0].scriptWitness.stack[0], key.pub);
    BOOST_CHECK(another != entry);
    // It does not collide with a Schnorr entry for the same data.
    cache.ComputeEntrySchnorr(another, sighash, tx.vin[0].scriptWitness.stack[0], XOnlyPubKey{key.pub});
    BOOST_CHECK(another != entry);

    // The cache is consulted before a signature is verified: once the entry of
    // an invalid signature is in it, that signature is taken to be valid.
    CMutableTransaction damaged_mtx{tx};
    damaged_mtx.vin[0].scriptWitness.stack[0] = damaged_sig;
    const CTransaction damaged_tx{damaged_mtx};
    BOOST_CHECK(!verify(damaged_tx, /*store=*/true));
    BOOST_CHECK(!cache.Get(other, /*erase=*/false));
    cache.Set(other);
    BOOST_CHECK(verify(damaged_tx, /*store=*/true));
}

BOOST_AUTO_TEST_SUITE_END()
