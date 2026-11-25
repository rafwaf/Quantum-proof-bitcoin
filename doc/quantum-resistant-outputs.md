# Quantum-resistant outputs

This document specifies the consensus and relay rules that this fork adds to
Bitcoin Core for quantum-resistant outputs. The rules are implemented and are
active on regtest only. They have no activation height on any other network
yet.

## Summary

- A new output type, Pay-to-Merkle-Root (P2MR), commits to a tree of scripts
  and to nothing else. It follows
  [BIP 360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki)
  version 0.12.1, with the one difference listed [below](#differences-from-bip-360).
- The scripts in the tree are tapscripts
  ([BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)).
  In a P2MR script, the signature opcodes also accept SLH-DSA-SHA2-128s public
  keys ([FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)).

A P2MR output never reveals an elliptic-curve public key unless one of its
scripts does and that script is used to spend it. An output whose scripts use
only SLH-DSA keys depends on no assumption other than the security of SHA-256.

## Output

The `scriptPubKey` is `OP_2 <32-byte Merkle root>`: a native witness program of
version 2. Its address is the bech32m encoding of that program, which starts
with `bc1z` under Bitcoin's prefix.

The Merkle root is the root of a script tree built as in
[BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki), from
`TapLeaf` and `TapBranch` tagged hashes. There is no internal key and no tweak.

## Spending

The witness of an input that spends a P2MR output is

    <initial stack element> ... <script> <control block> [<annex>]

and is validated as follows.

1. Fail if the witness has fewer than two elements.
2. If the first byte of the last element is `0x50`, that element is the annex.
   Fail if fewer than two elements remain without it. The annex is covered by
   signatures as in BIP 341 and is otherwise ignored.
3. The last remaining element is the control block and the one before it is the
   script. Fail unless the control block is `1 + 32 * m` bytes long, with
   `0 <= m <= 128`.
4. Fail unless the lowest bit of the first control block byte is set. The other
   seven bits are the leaf version.
5. Compute the tapleaf hash of the script and leaf version, and from it and the
   `m` nodes in the control block the Merkle root, as in BIP 341. Fail if the
   result differs from the witness program.
6. If the leaf version is `0xc0`, execute the script as a tapscript with the
   remaining elements as its initial stack, under the rules of BIP 342 and the
   additions below. For any other leaf version, succeed.

Signature hashes are computed exactly as for a BIP 342 script.

## SLH-DSA public keys

In a P2MR script, a 33-byte public key whose first byte is `0x80` is an SLH-DSA
public key: the byte `0x80` followed by the 32-byte SLH-DSA-SHA2-128s public
key. `OP_CHECKSIG`, `OP_CHECKSIGVERIFY` and `OP_CHECKSIGADD` treat it like a
BIP 340 public key, with these differences.

- A signature is 7856 bytes, or 7857 bytes when followed by a sighash type byte.
  As in BIP 341, that byte must not be `0x00` and must be a defined sighash
  type.
- The signature is verified with `slh_verify` of FIPS 205 (the "pure" variant),
  with the 32-byte signature hash as the message and an empty context string.
- A check of a non-empty signature costs 1000 units of the validation weight
  budget of BIP 342 instead of 50. A valid signature adds more than 7 times
  that to the budget by its own size.

As for BIP 340 keys, an empty signature makes the check fail without failing
the script, and any other signature that does not verify fails the script.
Public keys of any other unknown type keep their BIP 342 meaning: their checks
pass, for use by future rules.

Outside P2MR scripts nothing changes. In a Taproot (witness version 1) script
such a key is still a key of unknown type, as it is in Bitcoin.

## Limits

- An element of the initial stack may be larger than 520 bytes only if it is
  exactly 7856 or 7857 bytes long.
- `OP_RIPEMD160`, `OP_SHA1`, `OP_SHA256`, `OP_HASH160` and `OP_HASH256` fail on
  an element larger than 520 bytes.

These limits keep the work a script can demand per byte within what Bitcoin
scripts can already demand. Other opcodes can still copy or compare an element
of signature size, which costs less per byte of script than hashing 520-byte
elements does (see the `P2MR*` benchmarks in `src/bench/p2mr.cpp`). Signature
checks are bounded by the validation weight budget.

## Relay policy

A transaction that spends a P2MR output is standard under the same conditions
as a Taproot script path spend: no annex, a known leaf version, no `OP_SUCCESS`
opcode, no public key of unknown type, and initial stack elements of at most 80
bytes. Elements of 7856 or 7857 bytes are also allowed.

Before activation, spending a witness version 2 output is non-standard.

## Activation

The rules apply to blocks at and above the height `P2MRHeight` of the chain
parameters, which is reported by the `getdeploymentinfo` RPC as `p2mr`. Below
that height a witness version 2 output is an undefined witness program, as in
Bitcoin: anyone can spend it. On regtest the height is 0 and can be set with
`-testactivationheight=p2mr@<height>`.

## Differences from BIP 360

BIP 360 version 0.12 makes a script tree that consists of a single leaf (`m = 0`)
spendable by anyone, to reserve it for future use. Here such a tree is
validated like any other, so an output with one script cannot be taken by
whoever learns that script.

BIP 360 does not define post-quantum signatures. The SLH-DSA public keys above
are an addition.

## Tests

- `src/test/slhdsa_tests.cpp`: SLH-DSA against the NIST ACVP test vectors.
- `src/test/p2mr_tests.cpp`: script validation of P2MR spends.
- `test/functional/feature_p2mr.py`: the rules on a regtest node, before and
  after activation, through the mempool and in blocks.
