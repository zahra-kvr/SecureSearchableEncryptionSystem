from __future__ import annotations

import os, re, struct, hmac, hashlib, getpass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

L_KEY = 16
L_ADDR = 4
L_WORD = 16
NULL_ADDR = 0xFFFFFFFF


def _hmac(k, d):
    return hmac.new(k, d, hashlib.sha256).digest()

def _aes_ecb(k, b):
    c = Cipher(algorithms.AES(k), modes.ECB(), backend=default_backend())
    return c.encryptor().update(b) + c.encryptor().finalize()

def _prf_f(k, wb):
    # f_y(w): {0,1}^k x {0,1}^p -> {0,1}^{l+log2(m)}
    return _hmac(k, wb)[:L_KEY + L_ADDR]

def _prp_pi(k, wb):
    # pi_z(w): {0,1}^k x {0,1}^p -> {0,1}^p
    return _aes_ecb(k, _hmac(k, wb)[:L_WORD])

def _node_enc(k, pt):
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(k), modes.CTR(iv), backend=default_backend())
    return iv + c.encryptor().update(pt) + c.encryptor().finalize()

def _node_dec(k, d):
    c = Cipher(algorithms.AES(k), modes.CTR(d[:16]), backend=default_backend())
    return c.decryptor().update(d[16:]) + c.decryptor().finalize()


class _PRPPsi:
    # 8-round Feistel PRP over [0, m-1]
    def __init__(self, k, m):
        self.key, self.m = k, m
        if m > 1:
            bits = (m - 1).bit_length()
            self.half = (bits + 1) // 2
            self.bl = (self.half + 7) // 8

    def _f(self, r, rnd):
        # Feistel round: F(R) = HMAC(s, rnd || R)
        return int.from_bytes(_hmac(self.key, struct.pack(">I", rnd) + r.to_bytes(self.bl, 'big'))[:self.bl], 'big')

    def enc(self, x):
        # psi_s(x): 8-round Feistel (L,R) -> (R, L XOR F(R))
        if self.m <= 1:
            return 0
        mask = (1 << self.half) - 1
        L, R = x >> self.half, x & mask
        for rnd in range(8):
            L, R = R, L ^ (self._f(R, rnd) & mask)
        r = (L << self.half) | R
        return self.enc(r) if r >= self.m else r


def words_from_doc(t):
    return list(set(re.findall(r"[a-zA-Z0-9]+", t.lower())))


def keygen():
    # K = (s, y, z, doc_key) <- {0,1}^k
    return {"s": os.urandom(16), "y": os.urandom(16), "z": os.urandom(16), "doc_key": os.urandom(16)}


def key_to_str(k):
    return (k["s"] + k["y"] + k["z"] + k["doc_key"]).hex()


def str_to_key(s):
    raw = bytes.fromhex(s)
    return {"s": raw[0:16], "y": raw[16:32], "z": raw[32:48], "doc_key": raw[48:64]}


def build_index(key, docs):
    s, y, z = key["s"], key["y"], key["z"]
    # Build inverted index Delta' and D(w) for each word
    inv = {}
    for doc_id, text in docs:
        for w in words_from_doc(text):
            inv.setdefault(w, []).append(doc_id)
    for w in inv:
        inv[w].sort()

    m = sum(len(v) for v in inv.values())
    psi = _PRPPsi(s, m)
    A, first_info, ctr = {}, {}, 0

    for word in sorted(inv):
        doc_ids = inv[word]
        kappa = os.urandom(L_KEY)
        first_info[word] = (psi.enc(ctr), kappa)
        for j, doc_id in enumerate(doc_ids):
            is_last = j == len(doc_ids) - 1
            nk = os.urandom(L_KEY) if not is_last else b'\x00' * L_KEY
            na = psi.enc(ctr + 1) if not is_last else NULL_ADDR
            # Node N_{i,j} = <id || key_{i,j} || psi_s(ctr+1)>, stored at A[psi_s(ctr)]
            A[psi.enc(ctr)] = _node_enc(kappa, struct.pack(">I", doc_id) + nk + struct.pack(">I", na))
            kappa = nk
            ctr += 1

    # Pad A to size m with random values to hide |D(w)|
    while len(A) < m:
        a = psi.enc(ctr)
        if a not in A:
            A[a] = os.urandom(16 + 4 + L_KEY + L_ADDR)
        ctr += 1

    T = {}
    for word in sorted(inv):
        addr, kappa0 = first_info[word]
        v = struct.pack(">I", addr) + kappa0
        # T[pi_z(w)] = <addr(N_{i,1}) || key_{i,0}> XOR f_y(w)
        T[_prp_pi(z, word.encode())] = bytes(a ^ b for a, b in zip(v, _prf_f(y, word.encode())))

    enc_docs = {}
    for doc_id, text in docs:
        iv = os.urandom(16)
        c = Cipher(algorithms.AES(key["doc_key"]), modes.CTR(iv), backend=default_backend())
        enc_docs[doc_id] = iv + c.encryptor().update(text.encode()) + c.encryptor().finalize()

    return A, T, enc_docs


def trapdoor(key, word):
    # T_w = (pi_z(w), f_y(w))
    return (_prp_pi(key["z"], word.encode()), _prf_f(key["y"], word.encode()))


def search(A, T, tw):
    # alpha||key = T[gamma] XOR eta; walk linked list from A[alpha]
    gamma, eta = tw
    if gamma not in T:
        return []
    apk = bytes(a ^ b for a, b in zip(T[gamma], eta))
    addr = struct.unpack(">I", apk[:L_ADDR])[0]
    kappa = apk[L_ADDR:]
    if addr == NULL_ADDR or addr not in A:
        return []
    ids = []
    while True:
        node = _node_dec(kappa, A[addr])
        doc_id = struct.unpack(">I", node[:4])[0]
        nk = node[4:4 + L_KEY]
        na = struct.unpack(">I", node[4 + L_KEY:4 + L_KEY + L_ADDR])[0]
        ids.append(doc_id)
        if na == NULL_ADDR:
            break
        addr, kappa = na, nk
    return ids


def decrypt_doc(key, data):
    c = Cipher(algorithms.AES(key["doc_key"]), modes.CTR(data[:16]), backend=default_backend())
    return (c.decryptor().update(data[16:]) + c.decryptor().finalize()).decode()


SERVER_STORE = {}


def _make_user():
    while True:
        name = input("username: ").strip()
        if not name:
            print("no empty names")
            continue
        if name in SERVER_STORE:
            print("already exists")
            continue
        break

    key = keygen()
    keystr = key_to_str(key)
    print(f"user created: {name}")
    print(f"*** YOUR SECRET KEY (save this!): {keystr} ***")
    print("*** The server does NOT store your key. ***\n")

    try:
        n = int(input("how many docs? "))
    except ValueError:
        n = 0

    docs = []
    for i in range(n):
        t = input(f"doc {i + 1}: ")
        docs.append((i + 1, t))

    A, T, enc_docs = build_index(key, docs)

    SERVER_STORE[name] = {"A": A, "T": T, "enc_docs": enc_docs}
    print("encrypted and saved on server\n")


def _do_search():
    if not SERVER_STORE:
        print("no users on server\n")
        return

    name = input("user: ").strip()
    if name not in SERVER_STORE:
        print("not found\n")
        return

    try:
        keystr = getpass.getpass("key (will not echo): ").strip()
        key = str_to_key(keystr)
    except (ValueError, IndexError):
        print("invalid key\n")
        return

    store = SERVER_STORE[name]

    while True:
        q = getpass.getpass("search word (will not echo; type 'back' to exit): ").strip()
        if q == "back":
            print()
            break
        if q == "":
            continue

        tw = trapdoor(key, q)
        found_ids = search(store["A"], store["T"], tw)

        if not found_ids:
            print("no matches")
        else:
            print("matches:")
            for doc_id in found_ids:
                enc = store["enc_docs"].get(doc_id)
                if enc:
                    try:
                        print(f"  [{doc_id}] {decrypt_doc(key, enc)}")
                    except Exception:
                        print(f"  [{doc_id}] decode error")
        print("----")


def main():
    print("SSE-1: Searchable Symmetric Encryption")
    print("Curtmola et al. (ACM CCS 2006)\n")
    print("The server never sees your key or plaintext words.\n")

    while True:
        print("1  new user")
        print("2  search")
        print("3  list users on server")
        print("4  exit")
        c = input("> ").strip()
        if c == "1":
            _make_user()
        elif c == "2":
            _do_search()
        elif c == "3":
            for u in SERVER_STORE:
                print(u)
            print()
        elif c == "4":
            break
        else:
            print("??")

main()
