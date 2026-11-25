#!/usr/bin/env python3
# Copyright (c) 2026-present The Quantum-proof-bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only implementation of SLH-DSA-SHA2-128s (NIST FIPS 205).

It is written independently of the C++ implementation in src/crypto/slhdsa.cpp,
so that the two can be checked against each other. It builds whole trees level
by level instead of following the recursive algorithms of the standard.

WARNING: This code is slow and makes no attempt to protect secrets. Do not use
for anything but tests.
"""

import hashlib
import hmac
import unittest

# Parameters of SLH-DSA-SHA2-128s (FIPS 205, Table 2).
N = 16        # security parameter: length of every hash value in bytes
D = 7         # number of XMSS layers
HP = 9        # h': height of each XMSS tree (total height h = 63)
A = 12        # height of each FORS tree
K = 14        # number of FORS trees
W = 16        # Winternitz parameter
LEN1 = 32     # base-w digits of an n-byte message
LEN2 = 3      # base-w digits of the checksum
LEN = LEN1 + LEN2

MD_SIZE = 21         # ceil(k * a / 8)
IDX_TREE_SIZE = 7    # ceil((h - h') / 8)
IDX_LEAF_SIZE = 2    # ceil(h' / 8)

PUBLIC_KEY_SIZE = 2 * N
SECRET_KEY_SIZE = 4 * N
FORS_SIG_SIZE = K * (1 + A) * N
XMSS_SIG_SIZE = (LEN + HP) * N
SIGNATURE_SIZE = N + FORS_SIG_SIZE + D * XMSS_SIG_SIZE
assert SIGNATURE_SIZE == 7856

# Address types (FIPS 205 section 4.2).
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6


def _adrs(layer, tree, adrs_type, word1=0, word2=0, word3=0):
    """Build a compressed address (ADRSc, FIPS 205 section 11.2)."""
    return (bytes([layer]) + tree.to_bytes(8, 'big') + bytes([adrs_type]) +
            word1.to_bytes(4, 'big') + word2.to_bytes(4, 'big') + word3.to_bytes(4, 'big'))


class _Hasher:
    """The tweakable hash shared by F, H, T_l and PRF:
    Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || input))."""

    def __init__(self, pk_seed):
        assert len(pk_seed) == N
        self.seeded = hashlib.sha256(pk_seed + bytes(64 - N))

    def __call__(self, adrs, data):
        h = self.seeded.copy()
        h.update(adrs)
        h.update(data)
        return h.digest()[:N]


def _prf_msg(sk_prf, opt_rand, msg):
    return hmac.new(sk_prf, opt_rand + msg, hashlib.sha256).digest()[:N]


def _h_msg(r, pk_seed, pk_root, msg):
    """MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)."""
    seed = r + pk_seed + hashlib.sha256(r + pk_seed + pk_root + msg).digest()
    out = b''
    counter = 0
    while len(out) < MD_SIZE + IDX_TREE_SIZE + IDX_LEAF_SIZE:
        out += hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return out[:MD_SIZE + IDX_TREE_SIZE + IDX_LEAF_SIZE]


def _split_digest(digest):
    md = digest[:MD_SIZE]
    idx_tree = int.from_bytes(digest[MD_SIZE:MD_SIZE + IDX_TREE_SIZE], 'big') % (1 << ((D - 1) * HP))
    idx_leaf = int.from_bytes(digest[MD_SIZE + IDX_TREE_SIZE:], 'big') % (1 << HP)
    return md, idx_tree, idx_leaf


def _base_2b(data, b, out_len):
    """Algorithm 4: the first out_len b-bit digits of data, big endian."""
    value = int.from_bytes(data, 'big')
    total_bits = 8 * len(data)
    return [(value >> (total_bits - b * (i + 1))) & ((1 << b) - 1) for i in range(out_len)]


def _wots_digits(msg):
    digits = _base_2b(msg, 4, LEN1)
    csum = sum(W - 1 - d for d in digits)
    csum <<= 4  # (8 - ((len2 * lg_w) % 8)) % 8
    return digits + _base_2b(csum.to_bytes(2, 'big'), 4, LEN2)


def _wots_chain(hasher, value, start, steps, layer, tree, keypair, chain):
    for j in range(start, start + steps):
        value = hasher(_adrs(layer, tree, WOTS_HASH, keypair, chain, j), value)
    return value


def _wots_secret(hasher, sk_seed, layer, tree, keypair, chain):
    return hasher(_adrs(layer, tree, WOTS_PRF, keypair, chain, 0), sk_seed)


def _wots_pk_gen(hasher, sk_seed, layer, tree, keypair):
    ends = b''.join(
        _wots_chain(hasher, _wots_secret(hasher, sk_seed, layer, tree, keypair, i), 0, W - 1, layer, tree, keypair, i)
        for i in range(LEN))
    return hasher(_adrs(layer, tree, WOTS_PK, keypair), ends)


def _wots_sign(hasher, msg, sk_seed, layer, tree, keypair):
    return b''.join(
        _wots_chain(hasher, _wots_secret(hasher, sk_seed, layer, tree, keypair, i), 0, digit, layer, tree, keypair, i)
        for i, digit in enumerate(_wots_digits(msg)))


def _wots_pk_from_sig(hasher, sig, msg, layer, tree, keypair):
    ends = b''.join(
        _wots_chain(hasher, sig[i * N:(i + 1) * N], digit, W - 1 - digit, layer, tree, keypair, i)
        for i, digit in enumerate(_wots_digits(msg)))
    return hasher(_adrs(layer, tree, WOTS_PK, keypair), ends)


def _build_tree(leaves, node_hash):
    """Build a Merkle tree bottom-up. Returns the list of levels, leaves first.
    node_hash(height, index, left, right) computes an inner node."""
    levels = [leaves]
    height = 0
    while len(levels[-1]) > 1:
        height += 1
        below = levels[-1]
        levels.append([node_hash(height, i, below[2 * i], below[2 * i + 1]) for i in range(len(below) // 2)])
    return levels


def _auth_path(levels, idx):
    return b''.join(levels[j][(idx >> j) ^ 1] for j in range(len(levels) - 1))


def _climb(node, idx, auth, height, node_hash):
    """Compute a root from a node at the bottom of a tree and its authentication path."""
    for j in range(height):
        sibling = auth[j * N:(j + 1) * N]
        if (idx >> j) & 1:
            node = node_hash(j + 1, idx >> (j + 1), sibling, node)
        else:
            node = node_hash(j + 1, idx >> (j + 1), node, sibling)
    return node


def _xmss_tree(hasher, sk_seed, layer, tree):
    leaves = [_wots_pk_gen(hasher, sk_seed, layer, tree, i) for i in range(1 << HP)]
    return _build_tree(leaves, lambda height, index, left, right: hasher(_adrs(layer, tree, TREE, 0, height, index), left + right))


def _xmss_sign(hasher, msg, sk_seed, idx, layer, tree):
    """Returns (signature, root of the tree)."""
    levels = _xmss_tree(hasher, sk_seed, layer, tree)
    return _wots_sign(hasher, msg, sk_seed, layer, tree, idx) + _auth_path(levels, idx), levels[-1][0]


def _xmss_pk_from_sig(hasher, idx, sig, msg, layer, tree):
    node = _wots_pk_from_sig(hasher, sig[:LEN * N], msg, layer, tree, idx)
    return _climb(node, idx, sig[LEN * N:], HP, lambda height, index, left, right: hasher(_adrs(layer, tree, TREE, 0, height, index), left + right))


def _fors_sign(hasher, md, sk_seed, tree, keypair):
    """Returns (signature, FORS public key)."""
    sig = b''
    roots = b''
    for i, index in enumerate(_base_2b(md, A, K)):
        offset = i << A
        secrets = [hasher(_adrs(0, tree, FORS_PRF, keypair, 0, offset + j), sk_seed) for j in range(1 << A)]
        leaves = [hasher(_adrs(0, tree, FORS_TREE, keypair, 0, offset + j), secrets[j]) for j in range(1 << A)]
        # Within FORS, the index of a node at height z of tree i is offset by i * 2^(a - z).
        levels = _build_tree(leaves, lambda height, idx, left, right: hasher(_adrs(0, tree, FORS_TREE, keypair, height, (i << (A - height)) + idx), left + right))
        sig += secrets[index] + _auth_path(levels, index)
        roots += levels[-1][0]
    return sig, hasher(_adrs(0, tree, FORS_ROOTS, keypair), roots)


def _fors_pk_from_sig(hasher, sig, md, tree, keypair):
    roots = b''
    for i, index in enumerate(_base_2b(md, A, K)):
        part = sig[i * (1 + A) * N:(i + 1) * (1 + A) * N]
        node = hasher(_adrs(0, tree, FORS_TREE, keypair, 0, (i << A) + index), part[:N])
        roots += _climb(node, index, part[N:], A, lambda height, idx, left, right: hasher(_adrs(0, tree, FORS_TREE, keypair, height, (i << (A - height)) + idx), left + right))
    return hasher(_adrs(0, tree, FORS_ROOTS, keypair), roots)


def keygen(sk_seed, sk_prf, pk_seed):
    """FIPS 205 Algorithm 18. Returns (secret key, public key)."""
    assert len(sk_seed) == N and len(sk_prf) == N and len(pk_seed) == N
    hasher = _Hasher(pk_seed)
    pk_root = _xmss_tree(hasher, sk_seed, D - 1, 0)[-1][0]
    pk = pk_seed + pk_root
    return sk_seed + sk_prf + pk, pk


def sign_internal(msg, sk, addrnd=None):
    """FIPS 205 Algorithm 19. addrnd=None selects the deterministic variant."""
    assert len(sk) == SECRET_KEY_SIZE
    sk_seed, sk_prf, pk_seed, pk_root = (sk[i * N:(i + 1) * N] for i in range(4))
    hasher = _Hasher(pk_seed)
    opt_rand = pk_seed if addrnd is None else addrnd
    assert len(opt_rand) == N
    r = _prf_msg(sk_prf, opt_rand, msg)
    md, idx_tree, idx_leaf = _split_digest(_h_msg(r, pk_seed, pk_root, msg))
    sig_fors, node = _fors_sign(hasher, md, sk_seed, idx_tree, idx_leaf)
    sig = r + sig_fors
    for layer in range(D):
        sig_xmss, node = _xmss_sign(hasher, node, sk_seed, idx_leaf, layer, idx_tree)
        sig += sig_xmss
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
    assert node == pk_root
    assert len(sig) == SIGNATURE_SIZE
    return sig


def verify_internal(msg, sig, pk):
    """FIPS 205 Algorithm 20."""
    assert len(pk) == PUBLIC_KEY_SIZE
    if len(sig) != SIGNATURE_SIZE:
        return False
    pk_seed, pk_root = pk[:N], pk[N:]
    hasher = _Hasher(pk_seed)
    r = sig[:N]
    sig_fors = sig[N:N + FORS_SIG_SIZE]
    sig_ht = sig[N + FORS_SIG_SIZE:]
    md, idx_tree, idx_leaf = _split_digest(_h_msg(r, pk_seed, pk_root, msg))
    node = _fors_pk_from_sig(hasher, sig_fors, md, idx_tree, idx_leaf)
    for layer in range(D):
        node = _xmss_pk_from_sig(hasher, idx_leaf, sig_ht[layer * XMSS_SIG_SIZE:(layer + 1) * XMSS_SIG_SIZE], node, layer, idx_tree)
        idx_leaf = idx_tree % (1 << HP)
        idx_tree >>= HP
    return node == pk_root


def _encode(msg, context):
    """The message encoding of the "pure" external interface."""
    assert len(context) <= 255
    return bytes([0, len(context)]) + context + msg


def sign(msg, sk, context=b'', addrnd=None):
    """FIPS 205 Algorithm 22 (slh_sign)."""
    return sign_internal(_encode(msg, context), sk, addrnd)


def verify(msg, sig, pk, context=b''):
    """FIPS 205 Algorithm 24 (slh_verify)."""
    if len(context) > 255:
        return False
    return verify_internal(_encode(msg, context), sig, pk)


class TestFrameworkSlhDsa(unittest.TestCase):
    # From the NIST ACVP sample vectors (SLH-DSA-keyGen-FIPS205, tcId 1).
    SK_SEED = bytes.fromhex("173D04C938C1C36BF289C3C022D04B14")
    SK_PRF = bytes.fromhex("63AE23C41AA546DA589774AC20B745C4")
    PK_SEED = bytes.fromhex("0D794777914C99766827F0F09CA972BE")
    PK = bytes.fromhex("0D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C")

    def test_keygen(self):
        sk, pk = keygen(self.SK_SEED, self.SK_PRF, self.PK_SEED)
        self.assertEqual(pk, self.PK)
        self.assertEqual(sk, self.SK_SEED + self.SK_PRF + self.PK)

    def test_sign_verify(self):
        sk = self.SK_SEED + self.SK_PRF + self.PK
        msg = b'message'
        sig = sign(msg, sk)
        self.assertTrue(verify(msg, sig, self.PK))
        self.assertFalse(verify(b'massage', sig, self.PK))
        self.assertFalse(verify(msg, sig, self.PK, context=b'context'))
        self.assertFalse(verify(msg, sig[:-1], self.PK))
        self.assertFalse(verify(msg, sig + b'\x00', self.PK))
        for pos in (0, N, N + FORS_SIG_SIZE, SIGNATURE_SIZE - 1):
            damaged = bytearray(sig)
            damaged[pos] ^= 1
            self.assertFalse(verify(msg, bytes(damaged), self.PK))
        # The hedged variant gives a different signature that also verifies.
        hedged = sign(msg, sk, addrnd=bytes(range(N)))
        self.assertNotEqual(sig, hedged)
        self.assertTrue(verify(msg, hedged, self.PK))
