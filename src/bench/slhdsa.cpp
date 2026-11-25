// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/slhdsa.h>

#include <array>
#include <cassert>
#include <cstddef>

namespace {

struct KeyPair {
    std::array<unsigned char, slhdsa::SECRET_KEY_SIZE> sk;
    std::array<unsigned char, slhdsa::PUBLIC_KEY_SIZE> pk;
};

//! Fixed seeds, so that every run measures the same work.
template <unsigned char FILL>
constexpr std::array<unsigned char, slhdsa::N> Seed()
{
    std::array<unsigned char, slhdsa::N> seed;
    seed.fill(FILL);
    return seed;
}

KeyPair MakeKeyPair()
{
    KeyPair keys;
    slhdsa::KeyGen(Seed<1>(), Seed<2>(), Seed<3>(), keys.sk, keys.pk);
    return keys;
}

//! A transaction signature hash is 32 bytes.
constexpr std::array<unsigned char, 32> MESSAGE{};

} // namespace

static void SLHDSAKeyGen(benchmark::Bench& bench)
{
    bench.run([&] {
        ankerl::nanobench::doNotOptimizeAway(MakeKeyPair());
    });
}

static void SLHDSASign(benchmark::Bench& bench)
{
    const KeyPair keys{MakeKeyPair()};
    std::array<unsigned char, slhdsa::SIGNATURE_SIZE> sig;
    bench.run([&] {
        const bool ok{slhdsa::Sign(MESSAGE, {}, keys.sk, {}, sig)};
        assert(ok);
    });
}

static void SLHDSAVerify(benchmark::Bench& bench)
{
    const KeyPair keys{MakeKeyPair()};
    std::array<unsigned char, slhdsa::SIGNATURE_SIZE> sig;
    const bool signed_ok{slhdsa::Sign(MESSAGE, {}, keys.sk, {}, sig)};
    assert(signed_ok);
    bench.run([&] {
        const bool ok{slhdsa::Verify(MESSAGE, sig, {}, keys.pk)};
        assert(ok);
    });
}

BENCHMARK(SLHDSAKeyGen);
BENCHMARK(SLHDSASign);
BENCHMARK(SLHDSAVerify);
