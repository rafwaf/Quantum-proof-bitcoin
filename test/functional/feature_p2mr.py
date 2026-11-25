#!/usr/bin/env python3
# Copyright (c) 2026-present The Quantum-proof-bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Pay-to-Merkle-Root outputs (BIP 360) and the SLH-DSA signatures in their scripts.

The node activates P2MR at a height, so that the rules can be tested on both
sides of the activation:

- Before activation a witness v2 output is an unknown witness program: spending
  it is non-standard, and valid in a block with any witness.
- After activation it is a P2MR output: the witness must reveal a script of the
  committed script tree and satisfy it. The scripts are tapscripts (BIP 342)
  that additionally accept SLH-DSA public keys in the signature opcodes.
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    NORMAL_GBT_REQUEST_PARAMS,
    add_witness_commitment,
    create_block,
)
from test_framework.crypto import slhdsa
from test_framework.key import (
    compute_xonly_pubkey,
    generate_privkey,
    sign_schnorr,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    sha256,
)
from test_framework.psbt import (
    PSBT,
    PSBTMap,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_WITNESS_UTXO,
)
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_1,
    OP_2,
    OP_2DROP,
    OP_BOOLAND,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_DUP,
    OP_NUMEQUAL,
    OP_SHA256,
    OP_SWAP,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT,
    SIGHASH_SINGLE,
    SLHDSA_PUBKEY_TYPE,
    SLHDSA_SIGNATURE_SIZE,
    TaprootSignatureHash,
    p2mr_construct,
    slhdsa_script_pubkey,
    taproot_construct,
)
from test_framework.script_util import (
    script_to_p2sh_script,
    script_to_p2wsh_script,
)
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

ACTIVATION_HEIGHT = COINBASE_MATURITY + 50
AMOUNT = 100_000  # value of each output under test, in satoshi
FEE = 10_000

# Script errors, as they appear in reject reasons.
ERR_SLHDSA_SIG = "Invalid SLH-DSA signature)"
ERR_SLHDSA_SIG_SIZE = "Invalid SLH-DSA signature size"
ERR_SLHDSA_SIG_HASHTYPE = "Invalid SLH-DSA signature hash type"
ERR_SCHNORR_SIG = "Invalid Schnorr signature)"
ERR_CONTROL_SIZE = "Invalid P2MR control block size"
ERR_CONTROL_BYTE = "Lowest bit of the P2MR control byte must be set"
ERR_MISMATCH = "Witness program hash mismatch"
ERR_WITNESS_EMPTY = "Witness program was passed an empty witness"
ERR_PUSH_SIZE = "Push value size limit exceeded"
ERR_EVAL_FALSE = "Script evaluated without error but finished with a false/empty top stack element"
ERR_VALIDATION_WEIGHT = "Too much signature validation relative to witness weight"
ERR_UPGRADABLE_WITNESS_PROGRAM = "Witness version reserved for soft-fork upgrades"
ERR_UPGRADABLE_LEAF_VERSION = "Taproot version reserved for soft-fork upgrades"
ERR_UPGRADABLE_PUBKEYTYPE = "Public key version reserved for soft-fork upgrades"
ERR_OP_SUCCESS = "OP_SUCCESSx reserved for soft-fork upgrades"
ERR_WITNESS_NONSTANDARD = "bad-witness-nonstandard"
ERR_NONSTANDARD_INPUTS = "bad-txns-nonstandard-inputs"


def slhdsa_keygen(name):
    """Derive an SLH-DSA key pair from a name, so that the test is repeatable."""
    seeds = [sha256(f"{name}/{part}".encode())[:slhdsa.N] for part in ("sk_seed", "sk_prf", "pk_seed")]
    return slhdsa.keygen(*seeds)


def flip_bit(data, pos):
    """Return data with the lowest bit of the byte at pos flipped."""
    damaged = bytearray(data)
    damaged[pos] ^= 1
    return bytes(damaged)


class Utxo:
    def __init__(self, txid, vout, output):
        self.outpoint = COutPoint(int(txid, 16), vout)
        self.output = output


class P2MRTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=p2mr@{ACTIVATION_HEIGHT}"]]

    def fund(self, script_pubkeys):
        """Create one confirmed output for each of the given scriptPubKeys."""
        utxos = []
        for script_pubkey in script_pubkeys:
            res = self.wallet.send_to(from_node=self.node, scriptPubKey=script_pubkey, amount=AMOUNT)
            utxos.append(Utxo(res["txid"], res["sent_vout"], res["tx"].vout[res["sent_vout"]]))
        self.generate(self.wallet, 1)
        return utxos

    def create_spend(self, utxos):
        """A transaction that spends the given outputs to the wallet, without witnesses."""
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(utxo.outpoint) for utxo in utxos]
        tx.vout = [CTxOut(sum(utxo.output.nValue for utxo in utxos) - FEE, self.wallet.get_output_script())]
        tx.wit.vtxinwit = [CTxInWitness() for _ in utxos]
        return tx

    def sighash(self, tx, utxos, leaf, *, index=0, hash_type=SIGHASH_DEFAULT, annex=None):
        """The BIP 342 signature hash for spending input index through the given leaf."""
        # None of the scripts in this test uses OP_CODESEPARATOR.
        return TaprootSignatureHash(tx, [utxo.output for utxo in utxos], hash_type, index, scriptpath=True,
                                    leaf_script=leaf.script, leaf_ver=leaf.version, annex=annex, codeseparator_pos=0xffffffff)

    def set_witness(self, tx, leaf, stack, *, index=0, control_block=None, annex=None):
        """Set the witness of an input to spend through the given leaf with the given initial stack."""
        witness = list(stack) + [bytes(leaf.script), leaf.control_block if control_block is None else control_block]
        if annex is not None:
            witness.append(annex)
        tx.wit.vtxinwit[index].scriptWitness.stack = witness

    def check_mempool(self, tx, reason=None):
        """Check that the mempool would accept the transaction, or reject it for the given reason."""
        res = self.node.testmempoolaccept([tx.serialize().hex()])[0]
        if reason is None:
            assert res["allowed"], f"unexpected rejection: {res}"
        else:
            assert not res["allowed"], "transaction unexpectedly allowed"
            assert reason in res["reject-reason"], f"expected '{reason}' in '{res['reject-reason']}'"

    def check_block(self, txs, reason=None):
        """Check that a block with the transactions is accepted, or rejected for the given reason.
        An accepted block becomes the new tip."""
        tip = self.node.getbestblockhash()
        block = create_block(tmpl=self.node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS), txlist=txs)
        add_witness_commitment(block)
        block.solve()
        res = self.node.submitblock(block.serialize().hex())
        if reason is None:
            assert_equal(res, None)
            assert_equal(self.node.getbestblockhash(), block.hash_hex)
        else:
            assert res is not None, "block unexpectedly accepted"
            assert reason in res, f"expected '{reason}' in '{res}'"
            assert_equal(self.node.getbestblockhash(), tip)

    def check(self, tx, reason, *, mempool_reason=None):
        """Check that a block with the transaction is rejected for the given reason, and that
        the mempool rejects it too: for the same reason, unless a policy rule catches it first."""
        self.check_mempool(tx, mempool_reason or reason)
        self.check_block([tx], reason)

    def accept(self, tx):
        """Add a valid transaction to the mempool and mine it."""
        self.check_mempool(tx)
        txid = self.node.sendrawtransaction(tx.serialize().hex())
        block_hash = self.generate(self.wallet, 1)[0]
        assert txid in self.node.getblock(block_hash)["tx"]

    def deployment(self):
        return self.node.getdeploymentinfo()["deployments"]["p2mr"]

    def run_test(self):
        self.node = self.nodes[0]
        self.wallet = MiniWallet(self.node)
        self.generate(self.wallet, COINBASE_MATURITY + 30)

        self.log.info("Generate keys")
        self.schnorr_sec = generate_privkey()
        self.schnorr_pub = compute_xonly_pubkey(self.schnorr_sec)[0]
        self.other_schnorr_sec = generate_privkey()
        self.slh_sk1, self.slh_pk1 = slhdsa_keygen("key 1")
        self.slh_sk2, self.slh_pk2 = slhdsa_keygen("key 2")

        self.slh_script = CScript([slhdsa_script_pubkey(self.slh_pk1), OP_CHECKSIG])
        self.schnorr_script = CScript([self.schnorr_pub, OP_CHECKSIG])
        # The common case: a quantum-safe leaf next to a cheaper Schnorr leaf.
        self.hybrid = p2mr_construct([("slh", self.slh_script), ("schnorr", self.schnorr_script)])

        self.test_rpc()
        self.test_before_activation()
        self.test_structure()
        self.test_slhdsa_signatures()
        self.test_sighash_types()
        self.test_multisig()
        self.test_moving_and_copying_signatures()
        self.test_element_size()
        self.test_other_key_types()
        self.test_p2sh_wrapped()
        self.test_mixed_inputs()
        self.test_signing_rpcs()

    def test_rpc(self):
        self.log.info("P2MR outputs are recognized and have a witness v2 address")
        address = encode_segwit_address("bcrt", 2, self.hybrid.merkle_root)
        assert address.startswith("bcrt1z")
        decoded = self.node.decodescript(self.hybrid.scriptPubKey.hex())
        assert_equal(decoded["type"], "witness_v2_p2mr")
        assert_equal(decoded["address"], address)
        info = self.node.validateaddress(address)
        assert info["isvalid"]
        assert_equal(info["scriptPubKey"], self.hybrid.scriptPubKey.hex())
        assert_equal(info["witness_version"], 2)
        assert_equal(info["witness_program"], self.hybrid.merkle_root.hex())

    def test_before_activation(self):
        self.log.info("Before activation, a witness v2 output is an unknown witness program")
        assert self.node.getblockcount() < ACTIVATION_HEIGHT - 10
        assert_equal(self.deployment(), {"type": "buried", "active": False, "height": ACTIVATION_HEIGHT})

        early, last_early, kept = self.fund([self.hybrid.scriptPubKey] * 3)
        leaf = self.hybrid.leaves["schnorr"]

        # A spend that follows the P2MR rules is non-standard, like any spend of an undefined witness program.
        valid = self.create_spend([early])
        self.set_witness(valid, leaf, [sign_schnorr(self.schnorr_sec, self.sighash(valid, [early], leaf))])
        self.check_mempool(valid, ERR_NONSTANDARD_INPUTS)

        # In a block, anyone can spend the output with any witness.
        garbage = self.create_spend([early])
        garbage.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        self.check_mempool(garbage, ERR_NONSTANDARD_INPUTS)
        self.check_block([garbage])

        self.log.info("The rules start at the activation height, also for outputs created before it")
        self.generate(self.wallet, ACTIVATION_HEIGHT - 2 - self.node.getblockcount())
        assert_equal(self.deployment()["active"], False)
        # The last block before activation.
        garbage = self.create_spend([last_early])
        garbage.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        self.check_block([garbage])
        assert_equal(self.node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(self.deployment()["active"], True)

        # The first block after activation.
        garbage = self.create_spend([kept])
        garbage.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        self.check(garbage, ERR_MISMATCH, mempool_reason=ERR_WITNESS_NONSTANDARD)
        valid = self.create_spend([kept])
        self.set_witness(valid, leaf, [sign_schnorr(self.schnorr_sec, self.sighash(valid, [kept], leaf))])
        self.check_mempool(valid)
        self.check_block([valid])
        assert_equal(self.node.getblockcount(), ACTIVATION_HEIGHT)

        self.log.info("A reorganisation to before the activation height takes the rules away, and one back restores them")
        last_inactive = self.node.getblockhash(ACTIVATION_HEIGHT - 1)
        first_active = self.node.getblockhash(ACTIVATION_HEIGHT)
        self.node.invalidateblock(last_inactive)
        assert_equal(self.node.getblockcount(), ACTIVATION_HEIGHT - 2)
        assert_equal(self.deployment()["active"], False)
        # The spend that follows the P2MR rules returned to the mempool when its block was disconnected,
        # while the rules still applied to the next block. It is valid with and without them. The
        # spend with a meaningless witness, from the block before, did not return: it is not standard.
        assert_equal(self.node.getrawmempool(), [valid.txid_hex])
        # In a block, the output is anyone's to spend again.
        garbage = self.create_spend([kept])
        garbage.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        self.check_block([garbage])
        assert_equal(self.node.getblockcount(), ACTIVATION_HEIGHT - 1)
        assert_equal(self.deployment()["active"], True)
        assert_equal(self.node.getrawmempool(), [])
        # The original chain has more work. Going back to it brings back its blocks, and the rules with them.
        self.node.reconsiderblock(last_inactive)
        assert_equal(self.node.getbestblockhash(), first_active)
        assert_equal(self.node.getrawmempool(), [])
        # Its first block with the rules active spent the output that the other chain gave away.
        garbage = self.create_spend([kept])
        garbage.vout[0].nValue -= 1  # so that it is not the transaction that spent the output
        garbage.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        self.check_block([garbage], "bad-txns-inputs-missingorspent")

    def test_structure(self):
        self.log.info("A P2MR spend must reveal a script and its Merkle path")
        leaf = self.hybrid.leaves["schnorr"]
        utxo, annex_utxo, annex_unsigned_utxo = self.fund([self.hybrid.scriptPubKey] * 3)

        tx = self.create_spend([utxo])
        sig = sign_schnorr(self.schnorr_sec, self.sighash(tx, [utxo], leaf))
        self.set_witness(tx, leaf, [sig])
        self.check_mempool(tx)

        # The lowest bit of the control byte must be set.
        self.set_witness(tx, leaf, [sig], control_block=bytes([leaf.version]) + leaf.merklebranch)
        self.check(tx, ERR_CONTROL_BYTE)

        # The control block is the control byte and a whole number of 32-byte nodes.
        for control_block in (b"", leaf.control_block[:-1], leaf.control_block + b"\x00", bytes([leaf.version | 1]) + bytes(32 * 129)):
            self.set_witness(tx, leaf, [sig], control_block=control_block)
            # An empty control block is caught by the witness policy before the script is run.
            self.check(tx, ERR_CONTROL_SIZE, mempool_reason=None if control_block else ERR_WITNESS_NONSTANDARD)

        # The path must lead to the Merkle root in the output.
        for control_block in (
            bytes([leaf.version | 1]),  # no path: the leaf alone
            flip_bit(leaf.control_block, 1),  # a wrong sibling
            leaf.control_block + bytes(32),  # a path that is too long
            bytes([leaf.version | 1]) + self.schnorr_pub + leaf.merklebranch,  # a Taproot control block, with an internal key
        ):
            self.set_witness(tx, leaf, [sig], control_block=control_block)
            self.check(tx, ERR_MISMATCH)

        # The script must be the committed one.
        self.set_witness(tx, leaf, [sig])
        tx.wit.vtxinwit[0].scriptWitness.stack[-2] = bytes(CScript([self.schnorr_pub, OP_CHECKSIGVERIFY, OP_1]))
        self.check(tx, ERR_MISMATCH)

        # A witness needs a script and a control block.
        tx.wit.vtxinwit[0].scriptWitness.stack = []
        self.check_block([tx], ERR_WITNESS_EMPTY)
        tx.wit.vtxinwit[0].scriptWitness.stack = [leaf.control_block]
        self.check(tx, ERR_MISMATCH, mempool_reason=ERR_WITNESS_NONSTANDARD)
        # Two elements of which the last looks like an annex leave no control block.
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(leaf.script), bytes([ANNEX_TAG]) + leaf.merklebranch]
        self.check(tx, ERR_MISMATCH, mempool_reason=ERR_WITNESS_NONSTANDARD)

        # The script is executed: a signature of another key fails.
        self.set_witness(tx, leaf, [sign_schnorr(self.other_schnorr_sec, self.sighash(tx, [utxo], leaf))])
        self.check(tx, ERR_SCHNORR_SIG)

        self.set_witness(tx, leaf, [sig])
        self.accept(tx)

        self.log.info("An annex is non-standard, and signatures commit to it")
        annex = bytes([ANNEX_TAG]) + b"annex"
        tx = self.create_spend([annex_utxo])
        self.set_witness(tx, leaf, [sign_schnorr(self.schnorr_sec, self.sighash(tx, [annex_utxo], leaf, annex=annex))], annex=annex)
        self.check_mempool(tx, ERR_WITNESS_NONSTANDARD)
        self.check_block([tx])
        tx = self.create_spend([annex_unsigned_utxo])
        self.set_witness(tx, leaf, [sign_schnorr(self.schnorr_sec, self.sighash(tx, [annex_unsigned_utxo], leaf))], annex=annex)
        self.check_block([tx], ERR_SCHNORR_SIG)

        self.log.info("A tree with a single leaf is executed like any other")
        single = p2mr_construct([("only", self.schnorr_script)])
        leaf = single.leaves["only"]
        assert_equal(leaf.control_block, bytes([LEAF_VERSION_TAPSCRIPT | 1]))
        utxo, = self.fund([single.scriptPubKey])
        tx = self.create_spend([utxo])
        self.set_witness(tx, leaf, [sign_schnorr(self.other_schnorr_sec, self.sighash(tx, [utxo], leaf))])
        self.check(tx, ERR_SCHNORR_SIG)
        self.set_witness(tx, leaf, [])
        self.check_block([tx], "Operation not valid with the current stack size")
        self.set_witness(tx, leaf, [sign_schnorr(self.schnorr_sec, self.sighash(tx, [utxo], leaf))])
        self.accept(tx)

        self.log.info("Unknown leaf versions and OP_SUCCESS opcodes stay reserved for upgrades")
        upgradable = p2mr_construct([("leaf_version", self.schnorr_script, 0xc2), ("op_success", CScript(bytes([OP_1, 0x50])))])
        for name, reason in (("leaf_version", ERR_UPGRADABLE_LEAF_VERSION), ("op_success", ERR_OP_SUCCESS)):
            utxo, = self.fund([upgradable.scriptPubKey])
            tx = self.create_spend([utxo])
            self.set_witness(tx, upgradable.leaves[name], [])
            self.check_mempool(tx, reason)
            self.check_block([tx])

    def test_slhdsa_signatures(self):
        self.log.info("An SLH-DSA leaf is spent with an SLH-DSA signature")
        leaf = self.hybrid.leaves["slh"]
        mempool_utxo, block_utxo, schnorr_utxo = self.fund([self.hybrid.scriptPubKey] * 3)

        tx = self.create_spend([mempool_utxo])
        sig = slhdsa.sign(self.sighash(tx, [mempool_utxo], leaf), self.slh_sk1)
        assert_equal(len(sig), SLHDSA_SIGNATURE_SIZE)
        self.set_witness(tx, leaf, [sig])
        self.check_mempool(tx)

        self.log.info("Invalid SLH-DSA signatures are rejected")
        # Damage in each part of the signature: the randomizer, the FORS signature and the hypertree signature.
        for pos in (0, slhdsa.N, slhdsa.N + slhdsa.FORS_SIG_SIZE, SLHDSA_SIGNATURE_SIZE - 1):
            self.set_witness(tx, leaf, [flip_bit(sig, pos)])
            self.check(tx, ERR_SLHDSA_SIG)
        # A signature by another key.
        self.set_witness(tx, leaf, [slhdsa.sign(self.sighash(tx, [mempool_utxo], leaf), self.slh_sk2)])
        self.check(tx, ERR_SLHDSA_SIG)
        # A signature for another transaction.
        other = self.create_spend([mempool_utxo])
        other.vout[0].nValue -= 1
        self.set_witness(other, leaf, [sig])
        self.check(other, ERR_SLHDSA_SIG)
        # An explicit sighash type changes the message.
        self.set_witness(tx, leaf, [sig + bytes([SIGHASH_ALL])])
        self.check(tx, ERR_SLHDSA_SIG)
        # The explicit sighash type must be a defined one other than the default.
        for hash_type in (SIGHASH_DEFAULT, 0x04, 0x80, 0x84):
            self.set_witness(tx, leaf, [sig + bytes([hash_type])])
            self.check(tx, ERR_SLHDSA_SIG_HASHTYPE)
        # A signature that is too short. Its witness is too small to pay for an SLH-DSA signature check.
        for size in (1, 64, 65, 520):
            self.set_witness(tx, leaf, [sig[:size]])
            self.check_block([tx], ERR_VALIDATION_WEIGHT)
        # A larger witness element is only allowed with exactly the size of a signature.
        for size in (521, SLHDSA_SIGNATURE_SIZE - 1, SLHDSA_SIGNATURE_SIZE + 2):
            self.set_witness(tx, leaf, [(sig + bytes(2))[:size]])
            self.check_block([tx], ERR_PUSH_SIZE)
        # An empty signature makes the check fail without failing the script.
        self.set_witness(tx, leaf, [b""])
        self.check(tx, ERR_EVAL_FALSE)
        # A Schnorr signature does not satisfy an SLH-DSA key, nor an SLH-DSA signature a Schnorr key.
        self.set_witness(tx, leaf, [sign_schnorr(self.schnorr_sec, self.sighash(tx, [mempool_utxo], leaf))])
        self.check(tx, ERR_VALIDATION_WEIGHT)
        schnorr_leaf = self.hybrid.leaves["schnorr"]
        self.set_witness(tx, schnorr_leaf, [slhdsa.sign(self.sighash(tx, [mempool_utxo], schnorr_leaf), self.slh_sk1)])
        self.check(tx, "Invalid Schnorr signature size")

        # With a witness that is large enough to pay for the check, a signature of the wrong size is reported as such.
        padded = p2mr_construct([("padded", CScript([OP_DROP, slhdsa_script_pubkey(self.slh_pk1), OP_CHECKSIG])), ("schnorr", self.schnorr_script)])
        padded_utxo, = self.fund([padded.scriptPubKey])
        padded_tx = self.create_spend([padded_utxo])
        for size in (1, 64, 65, 520):
            self.set_witness(padded_tx, padded.leaves["padded"], [bytes(size), bytes(SLHDSA_SIGNATURE_SIZE)])
            self.check_block([padded_tx], ERR_SLHDSA_SIG_SIZE)

        self.log.info("Valid SLH-DSA spends are accepted through the mempool and directly in a block")
        self.set_witness(tx, leaf, [sig])
        self.accept(tx)
        tx = self.create_spend([block_utxo])
        self.set_witness(tx, leaf, [slhdsa.sign(self.sighash(tx, [block_utxo], leaf), self.slh_sk1)])
        self.check_block([tx])

        self.log.info("The Schnorr leaf of the same output still works")
        tx = self.create_spend([schnorr_utxo])
        self.set_witness(tx, schnorr_leaf, [sign_schnorr(self.schnorr_sec, self.sighash(tx, [schnorr_utxo], schnorr_leaf))])
        self.accept(tx)

    def test_sighash_types(self):
        self.log.info("SLH-DSA signatures support the sighash types of BIP 341")
        leaf = self.hybrid.leaves["slh"]
        utxo, = self.fund([self.hybrid.scriptPubKey])
        hash_type = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY
        tx = self.create_spend([utxo])
        tx.vout[0].nValue -= 1000
        sig = slhdsa.sign(self.sighash(tx, [utxo], leaf, hash_type=hash_type), self.slh_sk1) + bytes([hash_type])
        assert_equal(len(sig), SLHDSA_SIGNATURE_SIZE + 1)
        self.set_witness(tx, leaf, [sig])
        self.check_mempool(tx)
        # The signature covers the output at the index of its input.
        tx.vout[0].nValue -= 1
        self.check(tx, ERR_SLHDSA_SIG)
        tx.vout[0].nValue += 1
        # It does not cover other outputs.
        tx.vout.append(CTxOut(1000, self.wallet.get_output_script()))
        self.accept(tx)

    def test_multisig(self):
        self.log.info("SLH-DSA and Schnorr keys can be combined with OP_CHECKSIGADD")
        script = CScript([
            slhdsa_script_pubkey(self.slh_pk1), OP_CHECKSIG,
            slhdsa_script_pubkey(self.slh_pk2), OP_CHECKSIGADD,
            self.schnorr_pub, OP_CHECKSIGADD,
            OP_2, OP_NUMEQUAL,
        ])
        multisig = p2mr_construct([("2of3", script), ("schnorr", self.schnorr_script)])
        leaf = multisig.leaves["2of3"]
        utxo_slh, utxo_mixed = self.fund([multisig.scriptPubKey] * 2)

        # The signatures are consumed from the top of the stack: the first key's signature comes last.
        tx = self.create_spend([utxo_slh])
        msg = self.sighash(tx, [utxo_slh], leaf)
        sig1 = slhdsa.sign(msg, self.slh_sk1)
        sig2 = slhdsa.sign(msg, self.slh_sk2)
        sig_schnorr = sign_schnorr(self.schnorr_sec, msg)

        # One signature is not enough, and three are too many.
        self.set_witness(tx, leaf, [b"", b"", sig1])
        self.check(tx, ERR_EVAL_FALSE)
        self.set_witness(tx, leaf, [sig_schnorr, sig2, sig1])
        self.check(tx, ERR_EVAL_FALSE)
        # A signature given to the wrong key fails the script.
        self.set_witness(tx, leaf, [b"", sig1, sig2])
        self.check(tx, ERR_SLHDSA_SIG)
        self.set_witness(tx, leaf, [b"", flip_bit(sig2, 100), sig1])
        self.check(tx, ERR_SLHDSA_SIG)

        # Any two of the three keys.
        self.set_witness(tx, leaf, [sig_schnorr, b"", sig1])
        self.check_mempool(tx)
        self.set_witness(tx, leaf, [sig_schnorr, sig2, b""])
        self.check_mempool(tx)
        self.set_witness(tx, leaf, [b"", sig2, sig1])
        self.accept(tx)

        tx = self.create_spend([utxo_mixed])
        msg = self.sighash(tx, [utxo_mixed], leaf)
        self.set_witness(tx, leaf, [sign_schnorr(self.schnorr_sec, msg), slhdsa.sign(msg, self.slh_sk2), b""])
        self.check_block([tx])

    def test_moving_and_copying_signatures(self):
        self.log.info("A script can move an SLH-DSA signature, but cannot copy it to check it twice")
        pubkey = slhdsa_script_pubkey(self.slh_pk1)
        twice = CScript([OP_DUP, pubkey, OP_CHECKSIGVERIFY, pubkey, OP_CHECKSIG])
        # The SLH-DSA signature lies below the result of the first check, and is swapped to the top.
        moved = CScript([self.schnorr_pub, OP_CHECKSIG, OP_SWAP, pubkey, OP_CHECKSIG, OP_BOOLAND])
        tree = p2mr_construct([("twice", twice), ("moved", moved)])
        utxo_twice, utxo_moved = self.fund([tree.scriptPubKey] * 2)

        tx = self.create_spend([utxo_twice])
        leaf = tree.leaves["twice"]
        self.set_witness(tx, leaf, [slhdsa.sign(self.sighash(tx, [utxo_twice], leaf), self.slh_sk1)])
        self.check(tx, ERR_PUSH_SIZE)

        tx = self.create_spend([utxo_moved])
        leaf = tree.leaves["moved"]
        msg = self.sighash(tx, [utxo_moved], leaf)
        self.set_witness(tx, leaf, [slhdsa.sign(msg, self.slh_sk1), sign_schnorr(self.schnorr_sec, msg)])
        self.accept(tx)

    def test_element_size(self):
        self.log.info("Only P2MR witness stacks accept elements with the size of an SLH-DSA signature")
        drop = CScript([OP_DROP, OP_1])
        hash_and_drop = CScript([OP_SHA256, OP_DROP, OP_1])
        copy_and_drop = CScript([OP_DUP, OP_2DROP, OP_1])
        tree = [("drop", drop), [("hash", hash_and_drop), ("copy", copy_and_drop)]]
        p2mr = p2mr_construct(tree)
        p2tr = taproot_construct(self.schnorr_pub, tree)
        utxo_p2mr, utxo_hash, utxo_copy, utxo_p2tr = self.fund([p2mr.scriptPubKey] * 3 + [p2tr.scriptPubKey])

        tx = self.create_spend([utxo_p2mr])
        leaf = p2mr.leaves["drop"]
        # Larger elements are invalid, unless they have exactly the size of a signature.
        for size in (521, SLHDSA_SIGNATURE_SIZE - 1, SLHDSA_SIGNATURE_SIZE + 2, 10000):
            self.set_witness(tx, leaf, [bytes(size)])
            self.check_mempool(tx, ERR_WITNESS_NONSTANDARD)
            self.check_block([tx], ERR_PUSH_SIZE)
        # Elements up to the usual limit are valid, though large ones are non-standard as in Taproot.
        self.set_witness(tx, leaf, [bytes(80)])
        self.check_mempool(tx)
        self.set_witness(tx, leaf, [bytes(520)])
        self.check_mempool(tx, ERR_WITNESS_NONSTANDARD)
        # An element with the size of a signature is valid and standard, whatever the script does with it.
        self.set_witness(tx, leaf, [bytes(SLHDSA_SIGNATURE_SIZE + 1)])
        self.check_mempool(tx)
        self.set_witness(tx, leaf, [bytes(SLHDSA_SIGNATURE_SIZE)])
        self.accept(tx)

        # Except hashing it or copying it.
        for utxo, name in ((utxo_hash, "hash"), (utxo_copy, "copy")):
            tx = self.create_spend([utxo])
            leaf = p2mr.leaves[name]
            for size in (SLHDSA_SIGNATURE_SIZE, SLHDSA_SIGNATURE_SIZE + 1):
                self.set_witness(tx, leaf, [bytes(size)])
                self.check(tx, ERR_PUSH_SIZE)
            self.set_witness(tx, leaf, [bytes(520)])
            self.check_block([tx])

        # A Taproot output does not accept such elements.
        tx = self.create_spend([utxo_p2tr])
        leaf = p2tr.leaves["drop"]
        control_block = bytes([leaf.version + p2tr.negflag]) + p2tr.internal_pubkey + leaf.merklebranch
        for size in (SLHDSA_SIGNATURE_SIZE, SLHDSA_SIGNATURE_SIZE + 1):
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(size), bytes(leaf.script), control_block]
            self.check_block([tx], ERR_PUSH_SIZE)
        tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(80), bytes(leaf.script), control_block]
        self.accept(tx)

    def test_other_key_types(self):
        self.log.info("In a Taproot output an SLH-DSA key is an unknown key type, as in Bitcoin")
        p2tr = taproot_construct(self.schnorr_pub, [("slh", self.slh_script)])
        leaf = p2tr.leaves["slh"]
        utxo, = self.fund([p2tr.scriptPubKey])
        tx = self.create_spend([utxo])
        control_block = bytes([leaf.version + p2tr.negflag]) + p2tr.internal_pubkey + leaf.merklebranch
        # Any non-empty signature passes, which makes such an output unsafe. It is non-standard to spend.
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x01", bytes(leaf.script), control_block]
        self.check_mempool(tx, ERR_UPGRADABLE_PUBKEYTYPE)
        self.check_block([tx])

        self.log.info("In a P2MR script, keys of other unknown types stay reserved for upgrades")
        wrong_type = bytes([SLHDSA_PUBKEY_TYPE + 1]) + self.slh_pk1
        too_long = slhdsa_script_pubkey(self.slh_pk1) + b"\x00"
        tree = p2mr_construct([("wrong_type", CScript([wrong_type, OP_CHECKSIG])), ("too_long", CScript([too_long, OP_CHECKSIG]))])
        for name in ("wrong_type", "too_long"):
            utxo, = self.fund([tree.scriptPubKey])
            tx = self.create_spend([utxo])
            self.set_witness(tx, tree.leaves[name], [b"\x01"])
            self.check_mempool(tx, ERR_UPGRADABLE_PUBKEYTYPE)
            self.check_block([tx])

    def test_p2sh_wrapped(self):
        self.log.info("A witness v2 program inside P2SH is not a P2MR output")
        redeem_script = self.hybrid.scriptPubKey
        utxo, = self.fund([script_to_p2sh_script(redeem_script)])
        tx = self.create_spend([utxo])
        tx.vin[0].scriptSig = CScript([bytes(redeem_script)])
        tx.wit.vtxinwit[0].scriptWitness.stack = [b"\x01"]
        # It stays an undefined witness program: non-standard to spend, and anyone's in a block.
        self.check_mempool(tx, ERR_UPGRADABLE_WITNESS_PROGRAM)
        self.check_block([tx])

    def test_mixed_inputs(self):
        self.log.info("A transaction can spend P2MR outputs together with other outputs, in any order")
        other_script = CScript([OP_1])
        leaf = self.hybrid.leaves["schnorr"]
        for p2mr_index in (0, 1):
            p2mr_utxo, other_utxo = self.fund([self.hybrid.scriptPubKey, script_to_p2wsh_script(other_script)])
            utxos = [p2mr_utxo, other_utxo] if p2mr_index == 0 else [other_utxo, p2mr_utxo]
            tx = self.create_spend(utxos)
            tx.wit.vtxinwit[1 - p2mr_index].scriptWitness.stack = [bytes(other_script)]
            sig = sign_schnorr(self.schnorr_sec, self.sighash(tx, utxos, leaf, index=p2mr_index))
            self.set_witness(tx, leaf, [flip_bit(sig, 0)], index=p2mr_index)
            self.check(tx, ERR_SCHNORR_SIG)
            self.set_witness(tx, leaf, [sig], index=p2mr_index)
            self.accept(tx)

    def test_signing_rpcs(self):
        self.log.info("Signing a transaction keeps the witness of a P2MR input, and reports whether it is valid")
        leaf = self.hybrid.leaves["slh"]
        utxo, = self.fund([self.hybrid.scriptPubKey])
        tx = self.create_spend([utxo])
        sig = slhdsa.sign(self.sighash(tx, [utxo], leaf), self.slh_sk1)
        self.set_witness(tx, leaf, [sig])
        signed_hex = tx.serialize().hex()
        res = self.node.signrawtransactionwithkey(signed_hex, [])
        assert_equal(res["hex"], signed_hex)
        assert_equal(res["complete"], True)
        assert "errors" not in res

        damaged = self.create_spend([utxo])
        self.set_witness(damaged, leaf, [flip_bit(sig, 100)])
        damaged_hex = damaged.serialize().hex()
        res = self.node.signrawtransactionwithkey(damaged_hex, [])
        assert_equal(res["hex"], damaged_hex)
        assert_equal(res["complete"], False)
        assert_equal(res["errors"][0]["error"], "Invalid SLH-DSA signature")

        self.log.info("A PSBT with a finalized P2MR input is recognized as complete")
        def psbt_of(spend):
            unsigned = CTransaction(spend)
            unsigned.wit.vtxinwit = []
            return PSBT(
                g=PSBTMap({PSBT_GLOBAL_UNSIGNED_TX: unsigned.serialize()}),
                i=[PSBTMap({
                    PSBT_IN_WITNESS_UTXO: utxo.output.serialize(),
                    PSBT_IN_FINAL_SCRIPTWITNESS: spend.wit.vtxinwit[0].serialize(),
                })],
                o=[PSBTMap()],
            ).to_base64()

        res = self.node.finalizepsbt(psbt_of(tx))
        assert_equal(res["complete"], True)
        assert_equal(res["hex"], signed_hex)
        analysis = self.node.analyzepsbt(psbt_of(tx))
        assert_equal(analysis["inputs"][0]["is_final"], True)
        assert_equal(analysis["next"], "extractor")
        assert_equal(self.node.finalizepsbt(psbt_of(damaged))["complete"], False)

        self.accept(tx)


if __name__ == '__main__':
    P2MRTest(__file__).main()
