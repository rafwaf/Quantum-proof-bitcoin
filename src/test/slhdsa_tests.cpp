// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa.h>

#include <test/data/slhdsa_sha2_128s.json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <span>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;
using PublicKey = std::array<unsigned char, slhdsa::PUBLIC_KEY_SIZE>;
using SecretKey = std::array<unsigned char, slhdsa::SECRET_KEY_SIZE>;
using Signature = std::array<unsigned char, slhdsa::SIGNATURE_SIZE>;

/** The NIST ACVP test vectors for SLH-DSA-SHA2-128s. See the description in the JSON file. */
UniValue LoadVectors(const std::string& section)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::slhdsa_sha2_128s));
    BOOST_REQUIRE(vectors.isObject());
    return vectors[section].get_array();
}

Bytes Hex(const UniValue& test, const std::string& key)
{
    const auto bytes{TryParseHex<unsigned char>(test[key].get_str())};
    BOOST_REQUIRE(bytes.has_value());
    return *bytes;
}

template <size_t SIZE>
std::span<const unsigned char, SIZE> Fixed(const Bytes& bytes)
{
    BOOST_REQUIRE_EQUAL(bytes.size(), SIZE);
    return std::span<const unsigned char, SIZE>{bytes.data(), SIZE};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(slhdsa_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(nist_keygen)
{
    const UniValue tests{LoadVectors("keygen")};
    BOOST_CHECK_EQUAL(tests.size(), 10U);
    for (const UniValue& test : tests.getValues()) {
        BOOST_TEST_CONTEXT("tcId " << test["tcId"].getInt<int>())
        {
            SecretKey sk;
            PublicKey pk;
            slhdsa::KeyGen(Fixed<slhdsa::N>(Hex(test, "sk_seed")), Fixed<slhdsa::N>(Hex(test, "sk_prf")), Fixed<slhdsa::N>(Hex(test, "pk_seed")), sk, pk);
            BOOST_CHECK(Bytes(sk.begin(), sk.end()) == Hex(test, "sk"));
            BOOST_CHECK(Bytes(pk.begin(), pk.end()) == Hex(test, "pk"));
        }
    }
}

BOOST_AUTO_TEST_CASE(nist_siggen)
{
    const UniValue tests{LoadVectors("siggen")};
    BOOST_CHECK_EQUAL(tests.size(), 28U);
    for (const UniValue& test : tests.getValues()) {
        BOOST_TEST_CONTEXT("tcId " << test["tcId"].getInt<int>())
        {
            const Bytes sk{Hex(test, "sk")};
            const Bytes pk{Hex(test, "pk")};
            const Bytes msg{Hex(test, "message")};
            const Bytes context{Hex(test, "context")};
            const Bytes addrnd{Hex(test, "addrnd")};
            const Bytes expected{Hex(test, "signature")};
            Signature sig;
            if (test["interface"].get_str() == "internal") {
                slhdsa::SignInternal(msg, Fixed<slhdsa::SECRET_KEY_SIZE>(sk), addrnd, sig);
                BOOST_CHECK(slhdsa::VerifyInternal(msg, expected, Fixed<slhdsa::PUBLIC_KEY_SIZE>(pk)));
            } else {
                BOOST_CHECK(slhdsa::Sign(msg, context, Fixed<slhdsa::SECRET_KEY_SIZE>(sk), addrnd, sig));
                BOOST_CHECK(slhdsa::Verify(msg, expected, context, Fixed<slhdsa::PUBLIC_KEY_SIZE>(pk)));
            }
            BOOST_CHECK(Bytes(sig.begin(), sig.end()) == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(nist_sigver)
{
    const UniValue tests{LoadVectors("sigver")};
    BOOST_CHECK_EQUAL(tests.size(), 28U);
    size_t valid{0};
    for (const UniValue& test : tests.getValues()) {
        BOOST_TEST_CONTEXT("tcId " << test["tcId"].getInt<int>() << ": " << test["reason"].get_str())
        {
            const Bytes pk{Hex(test, "pk")};
            const Bytes msg{Hex(test, "message")};
            const Bytes sig{Hex(test, "signature")};
            bool result;
            if (test["interface"].get_str() == "internal") {
                result = slhdsa::VerifyInternal(msg, sig, Fixed<slhdsa::PUBLIC_KEY_SIZE>(pk));
            } else {
                result = slhdsa::Verify(msg, sig, Hex(test, "context"), Fixed<slhdsa::PUBLIC_KEY_SIZE>(pk));
            }
            BOOST_CHECK_EQUAL(result, test["valid"].get_bool());
            valid += result;
        }
    }
    // Make sure the vectors exercise both outcomes.
    BOOST_CHECK_EQUAL(valid, 4U);
}

BOOST_AUTO_TEST_CASE(sign_verify)
{
    SecretKey sk;
    PublicKey pk;
    const auto sk_seed{m_rng.randbytes<slhdsa::N, unsigned char>()};
    const auto sk_prf{m_rng.randbytes<slhdsa::N, unsigned char>()};
    const auto pk_seed{m_rng.randbytes<slhdsa::N, unsigned char>()};
    slhdsa::KeyGen(sk_seed, sk_prf, pk_seed, sk, pk);
    const Bytes msg{m_rng.randbytes(m_rng.randrange(100))};
    const Bytes context{m_rng.randbytes(m_rng.randrange(slhdsa::MAX_CONTEXT_SIZE + 1))};

    // Hedged and deterministic signatures differ, and both verify.
    Signature sig, deterministic;
    const auto addrnd{m_rng.randbytes<slhdsa::N, unsigned char>()};
    BOOST_REQUIRE(slhdsa::Sign(msg, context, sk, addrnd, sig));
    BOOST_REQUIRE(slhdsa::Sign(msg, context, sk, {}, deterministic));
    BOOST_CHECK(sig != deterministic);
    BOOST_CHECK(slhdsa::Verify(msg, sig, context, pk));
    BOOST_CHECK(slhdsa::Verify(msg, deterministic, context, pk));

    // Deterministic signing is repeatable.
    Signature again;
    BOOST_REQUIRE(slhdsa::Sign(msg, context, sk, {}, again));
    BOOST_CHECK(again == deterministic);

    // A different message, context or public key does not verify.
    Bytes other_msg{msg};
    other_msg.push_back(0);
    BOOST_CHECK(!slhdsa::Verify(other_msg, sig, context, pk));
    Bytes other_context{context};
    if (other_context.empty()) {
        other_context.push_back(0);
    } else {
        other_context.back() ^= 1;
    }
    BOOST_CHECK(!slhdsa::Verify(msg, sig, other_context, pk));
    for (size_t pos = 0; pos < pk.size(); ++pos) {
        PublicKey other_pk{pk};
        other_pk[pos] ^= 1 << m_rng.randrange(8);
        BOOST_CHECK(!slhdsa::Verify(msg, sig, context, other_pk));
    }

    // A signature of the wrong length does not verify.
    const std::span<const unsigned char> sig_span{sig};
    BOOST_CHECK(!slhdsa::Verify(msg, sig_span.first(slhdsa::SIGNATURE_SIZE - 1), context, pk));
    BOOST_CHECK(!slhdsa::Verify(msg, {}, context, pk));
    Bytes longer{sig.begin(), sig.end()};
    longer.push_back(0);
    BOOST_CHECK(!slhdsa::Verify(msg, longer, context, pk));

    // Changing any single byte of the signature makes it invalid.
    for (size_t pos = 0; pos < sig.size(); ++pos) {
        Signature damaged{sig};
        damaged[pos] ^= 1 << m_rng.randrange(8);
        BOOST_CHECK_MESSAGE(!slhdsa::Verify(msg, damaged, context, pk), "signature damaged at byte " << pos << " verified");
    }

    // A context longer than the maximum is rejected by both operations.
    const Bytes long_context(slhdsa::MAX_CONTEXT_SIZE + 1, 0);
    Signature unused;
    BOOST_CHECK(!slhdsa::Sign(msg, long_context, sk, {}, unused));
    BOOST_CHECK(!slhdsa::Verify(msg, sig, long_context, pk));

    // The internal and external interfaces sign different messages.
    BOOST_CHECK(!slhdsa::VerifyInternal(msg, sig, pk));
}

BOOST_AUTO_TEST_SUITE_END()
