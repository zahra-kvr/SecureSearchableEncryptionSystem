import os
import re
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ===== crypto stuff =====

def hmac_sha(key, msg):
    # probably not the best name but whatever
    return hmac.new(key, msg, hashlib.sha256).digest()

def encrypt(key, text_bytes):
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    e = c.encryptor()
    data = e.update(text_bytes) + e.finalize()
    return iv, data

def decrypt(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    d = c.decryptor()
    return d.update(data) + d.finalize()


# ===== indexing =====

def words_from_doc(s):
    # lowercase and split, ignore punctuation
    w = re.findall(r"[a-zA-Z0-9]+", s.lower())
    return list(set(w))

def build_stuff(docs, key):
    idx = {}
    encrypted = []

    for doc in docs:
        doc_id = doc[0]
        txt = doc[1]

        iv, ct = encrypt(key, txt.encode())
        encrypted.append((doc_id, iv, ct))

        ws = words_from_doc(txt)
        for x in ws:
            t = hmac_sha(key, x.encode())
            if t not in idx:
                idx[t] = []
            idx[t].append(doc_id)

    return encrypted, idx

def find_doc(enc_docs, wanted):
    for d in enc_docs:
        if d[0] == wanted:
            return d
    return None

def search_docs(idx, enc_docs, tok):
    res = []

    if tok not in idx:
        return res

    for did in idx[tok]:
        d = find_doc(enc_docs, did)
        if d:
            res.append((d[1], d[2]))

    return res


# ===== users =====

users = {}

def make_user():
    while True:
        name = input("username: ").strip()
        if not name:
            print("no empty names")
            continue
        if name in users:
            print("already exists")
            continue
        break

    key = os.urandom(16)
    print("user created:", name)

    try:
        n = int(input("how many docs? "))
    except:
        n = 0

    docs = []
    for i in range(n):
        t = input("doc " + str(i+1) + ": ")
        docs.append((i+1, t))

    enc, idx = build_stuff(docs, key)

    users[name] = {
        "k": key,
        "d": enc,
        "i": idx
    }

    print("saved\n")

def do_search():
    if not users:
        print("no users\n")
        return

    name = input("user: ").strip()
    if name not in users:
        print("not found\n")
        return

    u = users[name]

    while True:
        q = input("word (back to exit): ").strip()
        if q == "back":
            print()
            break
        if q == "":
            continue

        tok = hmac_sha(u["k"], q.encode())
        found = search_docs(u["i"], u["d"], tok)

        if not found:
            print("nothing")
        else:
            print("matches:")
            for iv, ct in found:
                try:
                    print("-", decrypt(u["k"], iv, ct).decode())
                except:
                    print("- decode error")

        print("----")


# ===== main =====

print("searchable encryption test\n")

while True:
    print("1 new user")
    print("2 search")
    print("3 list users")
    print("4 exit")

    c = input("> ").strip()

    if c == "1":
        make_user()
    elif c == "2":
        do_search()
    elif c == "3":
        for u in users:
            print(u)
        print()
    elif c == "4":
        break
    else:
        print("??\n")
