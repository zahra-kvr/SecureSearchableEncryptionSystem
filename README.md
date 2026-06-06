# Secure Searchable Encryption — SSE-1

Implementation of the SSE-1 construction from Curtmola et al. (ACM CCS 2006).

## What it does

A client encrypts documents, outsources them to an untrusted server, and later searches by keyword without the server seeing the keyword or document contents.

The server is **honest-but-curious**: follows the protocol but tries to learn from stored data and queries.

### Leakage (by design)

| Leakage | Meaning |
|---|---|
| **Search pattern** | Server sees if two searches are for the same word |
| **Access pattern** | Server sees which doc IDs match a query |
| **Count & size** | Number of docs and their encrypted size |

Everything else (keywords, document contents, word-doc mappings) stays hidden.

## The scheme

**Index** `I = (A, T)`:

- **Array `A`** — encrypted linked lists of doc IDs, scrambled at pseudo-random addresses. Each node holds `(doc_id, next_decryption_key, next_address)`. The server can walk a list but cannot see list sizes.
- **Look-up table `T`** — maps `π_z(word)` to a masked entry point. Only the trapdoor holder can unmask it.

**Protocol**:

```
Client                         Server
  │                              │
  │──── Trapdoor(w) = (γ, η) ───>│  γ = π_z(w), η = f_y(w)
  │                              │  α‖κ = T[γ] ⊕ η
  │                              │  walk A[α] → collect doc IDs
  │<──── D(w) = [doc_id, …] ─────│
  │<──── encrypted docs ─────────│
  │ decrypt with doc_key         │
```

**Primitives**:

| Primitive | Role |
|---|---|
| `f` PRF `{0,1}^k × {0,1}^p → {0,1}^{l+log₂(m)}` | Masks T entries (HMAC-SHA256) |
| `π` PRP `{0,1}^k × {0,1}^p → {0,1}^p` | T addresses (AES-ECB on 128-bit hash) |
| `ψ` PRP over `[0,m-1]` | Scrambles A positions (8-round Feistel) |
| `E` AES-128-CTR | Encrypts nodes and documents |

## Usage

```bash
pip install cryptography
python SSE.py
```

The server **never** stores your key. When you create a user, the key is shown once. You must provide it for every search. Search words and keys are typed hidden (no echo).

```
SSE-1: Searchable Symmetric Encryption
Curtmola et al. (ACM CCS 2006)

The server never sees your key or plaintext words.

1  new user
2  search
3  list users on server
4  exit
> 1
username: alice
user created: alice
*** YOUR SECRET KEY (save this!): <128 hex chars> ***
*** The server does NOT store your key. ***

how many docs? 2
doc 1: the quick brown fox
doc 2: jumps over the lazy dog
encrypted and saved on server

> 2
user: alice
key (will not echo):
search word (will not echo; type 'back' to exit):
matches:
  [1] the quick brown fox
----
```

## Reference

Curtmola, Garay, Kamara, Ostrovsky. *"Searchable Symmetric Encryption: Improved Definitions and Efficient Constructions"*. ACM CCS 2006. [PDF](74.pdf)
