// Copyright (c) 2026-present The Quantum-proof-bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <uint256.h>

#include <cassert>
#include <cstddef>
#include <vector>

// A P2MR witness stack may hold elements with the size of an SLH-DSA
// signature, which are much larger than the 520 bytes other scripts are limited
// to. These benchmarks measure what a script can make a validator do with such
// elements per byte of script, next to the most expensive thing a script can do
// with elements of the usual size, which is hashing them.

namespace {

constexpr script_verify_flags FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR};
constexpr int REPEATS{10'000};

/** Validate the spend of a P2MR output whose single leaf script repeats the
 *  given opcodes on witness elements of the given size. The opcodes must leave
 *  the stack as they found it. Reports the time per byte of script. */
void P2MRElementBench(benchmark::Bench& bench, size_t element_size, size_t element_count, const std::vector<opcodetype>& ops)
{
    CScript script;
    for (int i = 0; i < REPEATS; ++i) {
        for (const opcodetype op : ops) script << op;
    }
    const size_t repeated_bytes{script.size()};
    for (size_t i = 0; i < element_count; ++i) script << OP_DROP;
    script << OP_TRUE;

    const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, script)};
    const CScript script_pubkey{CScript() << OP_2 << ToByteVector(leaf_hash)};
    CScriptWitness witness;
    for (size_t i = 0; i < element_count; ++i) witness.stack.emplace_back(element_size, 0x42);
    witness.stack.emplace_back(script.begin(), script.end());
    witness.stack.push_back({TAPROOT_LEAF_TAPSCRIPT | 1});

    const BaseSignatureChecker checker;
    bench.batch(repeated_bytes).unit("byte").run([&] {
        ScriptError error;
        const bool ok{VerifyScript(CScript{}, script_pubkey, &witness, FLAGS, checker, &error)};
        assert(ok);
    });
}

} // namespace

// Copying: at most one element is copied per byte of script.
static void P2MRCopySignatureSizedElements(benchmark::Bench& bench)
{
    P2MRElementBench(bench, SLHDSA_SIGNATURE_SIZE + 1, 2, {OP_2DUP, OP_2DROP});
}

static void P2MRCopyMaxSizedElements(benchmark::Bench& bench)
{
    P2MRElementBench(bench, MAX_SCRIPT_ELEMENT_SIZE, 2, {OP_2DUP, OP_2DROP});
}

// Comparing: one comparison per two bytes of script.
static void P2MRCompareSignatureSizedElements(benchmark::Bench& bench)
{
    P2MRElementBench(bench, SLHDSA_SIGNATURE_SIZE + 1, 2, {OP_2DUP, OP_EQUALVERIFY});
}

// Hashing elements of the usual maximum size: three hashes per seven bytes of script.
static void P2MRHashMaxSizedElements(benchmark::Bench& bench)
{
    P2MRElementBench(bench, MAX_SCRIPT_ELEMENT_SIZE, 3, {OP_3DUP, OP_RIPEMD160, OP_DROP, OP_RIPEMD160, OP_DROP, OP_RIPEMD160, OP_DROP});
}

BENCHMARK(P2MRCopySignatureSizedElements);
BENCHMARK(P2MRCopyMaxSizedElements);
BENCHMARK(P2MRCompareSignatureSizedElements);
BENCHMARK(P2MRHashMaxSizedElements);
