# NutChain Game Engine Specification

## 1. Overview & Design Goals

NutChain is a turn-based game engine that uses Nostr events as the substrate for all game data. Events are cryptographically signed, hash-referenced, and form a verifiable directed acyclic graph (DAG) that any party can replay to reconstruct authoritative game state.

The engine provides:

- **Verifiable, ordered game state** via a Nostr event DAG
- **Fully self-sovereign gameplay** — no trusted third party; the player set is the authority
- **Unbiasable randomness** via Cashu's BDHKE blinding scheme extended to a Threshold OPRF across the player set
- **Arbitrary game rules** expressed as a deterministic pure function over the event DAG
- **Private game state** via SHA-256 commit-reveal pairs

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **BDHKE** | Blind Diffie-Hellman Key Exchange. Cashu's blinding scheme: `B' = Hash_to_curve(x) + r*G`, `C' = k*B'`, `C = C' - r*K` |
| **Threshold OPRF** | Threshold Oblivious Pseudorandom Function. Distributes the BDHKE signing key `k` across `n` parties requiring `t` to cooperate to produce a valid response |
| **DLEQ Proof** | Discrete Log Equality proof. Proves `log_G(S_i) == log_{B'}(C'_i)` without revealing the secret share `s_i` |
| **Pedersen DKG** | The Distributed Key Generation protocol (from FROST RFC 9591) used to distribute shares of the group signing key `k` |
| **FROST** | Used exclusively to refer to the Pedersen DKG phase. Not used to describe the signing phase, which is a Threshold OPRF |
| **DASoR** | Deterministic Authoritative Source of Randomness. The full protocol by which unbiasable random seeds are produced |
| **Signing set** | The specific subset `S` of `t` players who respond to a given `RANDOMNESS_REQUEST` |
| **Event DAG** | The directed acyclic graph of hash-linked Nostr events that encodes all game state |
| **Group key** | The aggregated public key `K = Σ C_{i,0}` derived from all players' DKG Round 1 commitments |

---

## 3. Actors

| Actor | Role |
|-------|------|
| **Players** | Participate in gameplay, DKG, and Threshold OPRF signing rounds |
| **Game Rule Implementation** | A deterministic pure function `f(ordered_events) → game_state`, identified by hash at genesis |
| **Verifiers** | Any party that replays the event DAG to independently verify game state and randomness proofs |

No external authority exists. The player set collectively holds the group signing key and acts as the randomness authority.

---

## 4. Nostr Event Schema

### 4.1 Base Event Fields

Every NutChain event is a standard Nostr event carrying these fields in addition to the Nostr base fields:

| Field | Description |
|-------|-------------|
| `game_id` | Unique identifier for the game instance (the `GAME_CREATE` event ID) |
| `e` tag | Hash of the parent event. Enforces causal ordering in the DAG |
| `pubkey` | Author's Nostr public key |
| `sig` | Nostr Schnorr signature over the event |

### 4.2 Event Kind Registry

| Kind | Name | Phase | Description |
|------|------|-------|-------------|
| `30000` | `GAME_CREATE` | Setup | Genesis event. Encodes rules hash, player pubkeys, threshold parameters, and timeout |
| `30001` | `PLAYER_JOIN` | Setup | Player accepts game invite. References `GAME_CREATE` |
| `30010` | `DKG_ROUND_1` | Setup | Player publishes Feldman polynomial commitments and proof of knowledge |
| `30011` | `DKG_ROUND_2` | Setup | Player publishes per-peer encrypted secret shares |
| `30012` | `GAME_START` | Setup | Commits the group public key `K`. Game begins upon publication |
| `30002` | `GAME_ACTION` | Gameplay | A player action. References its parent event to enforce turn ordering |
| `30003` | `RANDOMNESS_REQUEST` | Gameplay | Player commits to `SHA-256(x)`, publishes blinded message `B'` and signing context |
| `30004` | `TOPRF_PARTIAL` | Gameplay | A co-signer's partial evaluation `C'_i = s_i * B'` and DLEQ proof `π_i` |
| `30005` | `RANDOMNESS_RESPONSE` | Gameplay | Requester publishes the aggregated blind signature `C'` |
| `30006` | `RANDOMNESS_REVEAL` | Gameplay | Player reveals `x`, blinding factor `r`, and unblinded signature `C` |
| `30007` | `COMMIT` | Gameplay | SHA-256 commitment for private game state |
| `30008` | `REVEAL` | Gameplay | Preimage reveal for a prior `COMMIT` event |
| `30009` | `GAME_END` | Teardown | Final state assertion. References the full event chain |

---

## 5. Game Lifecycle

```
 SETUP PHASE
 ────────────────────────────────────────────────────────────
 GAME_CREATE
   └── PLAYER_JOIN × n
         └── DKG_ROUND_1 × n
               └── DKG_ROUND_2 × n
                     └── GAME_START  ◄─ group key K committed here

 GAMEPLAY PHASE (repeating)
 ────────────────────────────────────────────────────────────
 GAME_ACTION
   └── (if randomness needed)
         RANDOMNESS_REQUEST
           └── TOPRF_PARTIAL × t          (co-signers respond)
                 └── RANDOMNESS_RESPONSE  (requester aggregates)
                       └── RANDOMNESS_REVEAL
                             └── GAME_ACTION (next turn)

 TEARDOWN
 ────────────────────────────────────────────────────────────
 GAME_END
```

---

## 6. Game Setup Phase

### 6.1 GAME_CREATE

The founding player publishes the genesis event. All subsequent events reference its ID as the `game_id`.

```json
{
  "kind": 30000,
  "content": {
    "rules_hash": "<sha256 of game rule implementation>",
    "players": [
      "<nostr pubkey 1>",
      "<nostr pubkey 2>",
      "<nostr pubkey n>"
    ],
    "frost_n": 4,
    "frost_t": 3,
    "turn_timeout_seconds": 300
  },
  "tags": [["d", "<game_id>"]]
}
```

- `rules_hash` — SHA-256 of the game rule implementation. All clients must run a matching implementation or their state derivations are invalid.
- `frost_t` — signing threshold: `floor(2n/3) + 1` (Byzantine majority, consistent with Fedimint). For `n=4`, `t=3`. For `n=3`, `t=3`. For `n=7`, `t=5`.
- `turn_timeout_seconds` — after this duration without a required event from a player, any peer may declare forfeit.

### 6.2 DKG Round 1

Each player `i` independently generates a random polynomial `f_i(x)` of degree `t-1` over the scalar field:

```
f_i(x) = a_{i,0} + a_{i,1}*x + ... + a_{i,t-1}*x^{t-1}
```

The constant term `a_{i,0}` becomes player `i`'s contribution to the group secret. Player `i` publishes:

- **Feldman commitments:** `C_{i,k} = a_{i,k} * G` for `k = 0..t-1`
- **Proof of knowledge** of `a_{i,0}`: a Schnorr signature `(R, s)` over the player's index and commitments, binding the polynomial to the player's Nostr key. This prevents rogue key attacks.

```json
{
  "kind": 30010,
  "content": {
    "game_id": "<game_id>",
    "player_index": 1,
    "commitments": [
      "<hex-encoded point C_{i,0}>",
      "<hex-encoded point C_{i,1}>",
      "<hex-encoded point C_{i,t-1}>"
    ],
    "proof_of_knowledge": {
      "R": "<hex-encoded point>",
      "s": "<hex-encoded scalar>"
    }
  },
  "tags": [["e", "<GAME_CREATE event id>"], ["d", "<game_id>"]]
}
```

Each player verifies all peers' proofs of knowledge before proceeding to Round 2.

### 6.3 DKG Round 2

Each player `i` computes a secret share for each peer `j` by evaluating their polynomial at index `j`:

```
share_{i→j} = f_i(j)
```

This value is encrypted to `j`'s Nostr public key (NIP-44 encrypted direct message semantics) so only `j` can read it. All encrypted shares are broadcast in a single `DKG_ROUND_2` event:

```json
{
  "kind": 30011,
  "content": {
    "game_id": "<game_id>",
    "player_index": 1,
    "shares": [
      {
        "recipient_index": 2,
        "recipient_pubkey": "<nostr pubkey>",
        "encrypted_share": "<NIP-44 ciphertext of f_i(2)>"
      },
      {
        "recipient_index": 3,
        "recipient_pubkey": "<nostr pubkey>",
        "encrypted_share": "<NIP-44 ciphertext of f_i(3)>"
      }
    ]
  },
  "tags": [
    ["e", "<DKG_ROUND_1 event id of this player>"],
    ["d", "<game_id>"]
  ]
}
```

Upon receiving all peers' `DKG_ROUND_2` events, each player `j`:

**Verifies** each received share against the sender's Round 1 commitments:
```
share_{i→j} * G == Σ_{k=0}^{t-1} C_{i,k} * j^k
```
A share that fails verification indicates a misbehaving peer. Abort and surface the invalid `DKG_ROUND_2` event as evidence.

**Derives** their final secret share by summing all received shares:
```
s_j = Σ_i share_{i→j}
```

`s_j` is never published. It is the player's long-term secret for this game.

**Derives** the group public key (computable by anyone from Round 1 events):
```
K = Σ_i C_{i,0}
```

**Derives** their public key share (also computable by anyone):
```
S_j = s_j * G  ==  Σ_i Σ_{k=0}^{t-1} C_{i,k} * j^k
```

### 6.4 GAME_START

Any player publishes `GAME_START` once all `DKG_ROUND_2` events are present and verified:

```json
{
  "kind": 30012,
  "content": {
    "game_id": "<game_id>",
    "group_pubkey": "<hex-encoded point K>",
    "dkg_round_2_event_ids": [
      "<event id>",
      "<event id>",
      "<event id>",
      "<event id>"
    ]
  },
  "tags": [["e", "<GAME_CREATE event id>"], ["d", "<game_id>"]]
}
```

`K` is immutable for the lifetime of the game. No key changes are permitted after `GAME_START` is published. Game rules begin applying to events published after this point.

---

## 7. Game State & Event DAG

### 7.1 Ordering

Every event (except `GAME_CREATE`) references the hash of its parent event via the `e` tag. This forms a hash-linked chain that enforces causal ordering. Because each event commits to its parent's hash, the full history is tamper-evident: altering any event invalidates all subsequent events.

### 7.2 State Derivation

Game state is derived by replaying all valid events in topological order through the game rule function:

```
state_n = f(event_0, event_1, ..., event_n)
```

This function is deterministic and pure. Any implementation whose SHA-256 matches `rules_hash` from `GAME_CREATE` will produce identical state from identical input. Clients that cannot match `rules_hash` must not participate.

### 7.3 Fork Resolution

If two events reference the same parent (a fork), the canonical branch is determined by:

1. Earliest Nostr event `created_at` timestamp
2. If timestamps are equal, lexicographically lowest event ID (hex)

Forked events are not discarded — they remain in the DAG as evidence of equivocation.

---

## 8. Deterministic Authoritative Source of Randomness (DASoR)

The DASoR protocol produces random seeds that are unbiasable by any individual player and by any coalition of fewer than `t` players. The random seed is a joint product of the requesting player's secret `x` and the group signing key `k`, where neither party can compute the result without the other's contribution.

### 8.1 Cryptographic Primitives

**BDHKE (Cashu):**

The base single-signer scheme:
```
Blinding:   B' = Hash_to_curve(x) + r*G
Signing:    C' = k * B'
Unblinding: C  = C' - r*K  =  k * Hash_to_curve(x)
Verify:     C  == k * Hash_to_curve(x)  using public key K = k*G
```

`C` is a deterministic function of `x` and `k`. Neither `x` (known only to the player) nor `k` (held as shares across players) alone determines the output.

**Threshold OPRF:**

The multi-signer extension. Each player `i` holds a secret share `s_i` of the group key `k`. To compute `k * B'` without any single player knowing `k`:

1. Each co-signer `i` computes a partial evaluation: `C'_i = s_i * B'`
2. Each co-signer proves correctness via a DLEQ proof (see Section 8.4)
3. The requester reconstructs `C' = k * B'` via Lagrange interpolation over any `t` valid partial evaluations

**Why not FROST Schnorr?**

FROST produces `(R, z)` Schnorr signature pairs. The BDHKE unblinding step requires the multiplicative structure `C = C' - r*K`, which only holds when `C' = k * B'`. A Schnorr signature over `B'` cannot be unblinded into `k * Hash_to_curve(x)`. The Threshold OPRF preserves this structure. FROST's Pedersen DKG is reused for key distribution, but the signing protocol is distinct.

### 8.2 Security Properties

| Property | Mechanism |
|----------|-----------|
| No single player can bias the outcome | Threshold OPRF: `t` colluders required to control `k` |
| Requester cannot bias the outcome | Requester controls `x` but not `k`; cannot evaluate `k*Hash_to_curve(x)` without co-signers |
| Co-signers cannot bias the outcome | Co-signers sign the blinded `B'` without knowing `x`; cannot evaluate the result |
| Grinding is mitigated | `SHA-256(x)` committed on-chain before any partial response is returned |
| Tokens are context-bound | Each signing request commits to `(game_id, turn, action_type, parent_event_hash)` |
| Partial responses are individually verifiable | DLEQ proofs allow anyone to reject invalid partial evaluations |

### 8.3 Protocol Flow

```
1. Player generates secret x  (uniformly random, e.g. 32 bytes from CSPRNG)

2. Player publishes RANDOMNESS_REQUEST:
     commitment = SHA-256(x)
     B'         = Hash_to_curve(x) + r*G    (r = secret blinding factor)
     context    = SHA-256(game_id || turn_number || action_type || parent_event_hash)
     num_values = number of derived random values this action will consume

3. Each co-signer i in signing set S (|S| = t) publishes TOPRF_PARTIAL:
     C'_i = s_i * B'
     π_i  = DLEQ proof that C'_i is consistent with S_i = s_i*G

4. Requester collects t valid TOPRF_PARTIAL events:
     Verifies each π_i against the corresponding public key share S_i
     Applies Lagrange interpolation to reconstruct:
       C' = Σ_{i∈S} λ_i * C'_i

5. Requester publishes RANDOMNESS_RESPONSE:
     C' = aggregated blind evaluation

6. Requester publishes RANDOMNESS_REVEAL:
     x  = original secret
     r  = blinding factor
     C  = C' - r*K     (unblinded result)

7. Verification (anyone):
     Check: SHA-256(x) matches commitment in RANDOMNESS_REQUEST
     Check: Hash_to_curve(x)*K_scalar == C  ← restate as: verify C against K and x
     Formally: C is valid iff the discrete log of C w.r.t. Hash_to_curve(x) equals
               the discrete log of K w.r.t. G

8. Seed derivation:
     seed = SHA-256(C.x_coordinate || context)
```

### 8.4 Threshold OPRF Signing Detail

#### DLEQ Proof

A DLEQ (Discrete Log Equality) proof demonstrates that the same secret scalar `s_i` was used in both `S_i = s_i * G` and `C'_i = s_i * B'`, without revealing `s_i`. Public key shares `S_i` are computable by anyone from the DKG Round 1 commitments.

**Construction (Sigma protocol, non-interactive via Fiat-Shamir):**

```
Public inputs:  G, B', S_i, C'_i
Prover knows:   s_i

1. Sample random nonce:  k ←$ Z_q
2. Compute commitments:  A = k*G
                         Z = k*B'
3. Compute challenge:    e = SHA-256("NUTCHAIN_DLEQ_v1" || G || B' || S_i || C'_i || A || Z)
4. Compute response:     s = k - s_i*e   (mod group order q)

Proof: π_i = (e, s)
```

**Verification:**

```
A' = s*G + e*S_i
Z' = s*B' + e*C'_i
Check: e == SHA-256("NUTCHAIN_DLEQ_v1" || G || B' || S_i || C'_i || A' || Z')
```

A `TOPRF_PARTIAL` event whose proof fails this check is invalid and must be ignored.

#### Lagrange Interpolation

Given signing set `S ⊆ {1..n}` with `|S| = t`, the Lagrange coefficient for signer `i` evaluated at `0` is:

```
λ_i = Π_{j∈S, j≠i} (0 - j) / (i - j)   (mod group order q)
```

The aggregated blind evaluation:

```
C' = Σ_{i∈S} λ_i * C'_i
```

The choice of signing set `S` does not affect the result — any `t` valid partial evaluations produce the same `C'`. Requesters should use the first `t` valid `TOPRF_PARTIAL` events received.

#### TOPRF_PARTIAL Event Schema

```json
{
  "kind": 30004,
  "content": {
    "game_id": "<game_id>",
    "randomness_request_event_id": "<event id of RANDOMNESS_REQUEST>",
    "player_index": 2,
    "partial_response": "<hex-encoded point C'_i>",
    "public_key_share": "<hex-encoded point S_i>",
    "dleq_proof": {
      "e": "<hex-encoded scalar>",
      "s": "<hex-encoded scalar>"
    }
  },
  "tags": [
    ["e", "<RANDOMNESS_REQUEST event id>"],
    ["d", "<game_id>"]
  ]
}
```

### 8.5 Multi-Value Derivation

When a single game action requires multiple independent random values, they are derived from one seed using a counter. The number of values must be declared in `num_values` within `RANDOMNESS_REQUEST` so co-signers and verifiers know the full scope of the request.

```
seed    = SHA-256(C.x_coordinate || context)
value_0 = SHA-256(seed || 0x00000000)
value_1 = SHA-256(seed || 0x00000001)
value_2 = SHA-256(seed || 0x00000002)
...
value_k = SHA-256(seed || k as big-endian uint32)
```

To map a value to a range `[0, N)`:

```
result = value_k interpreted as big-endian uint256, mod N
```

For small `N` relative to 2^256, modular bias is negligible. Game rules may specify rejection sampling for applications requiring strict uniformity.

### 8.6 Anti-Grinding

The commitment `SHA-256(x)` is published in `RANDOMNESS_REQUEST` before any co-signer sees or acts on the request. A player wishing to grind a favorable outcome must:

1. Choose `x`
2. Publicly commit to it on Nostr
3. Receive `t` partial responses
4. Unblind to learn the seed
5. Discard the token and start over with a new `x`

Step 5 constitutes abandonment of a randomness request. The `turn_timeout_seconds` clock begins at `RANDOMNESS_REQUEST` publication. If `RANDOMNESS_REVEAL` is not published before timeout, any peer may declare forfeit (see Section 10).

All `RANDOMNESS_REQUEST` events are permanently on-chain. Repeated requests against the same game context without a corresponding reveal are publicly observable evidence of grinding.

### 8.7 Context Binding

Each randomness token is cryptographically bound to a unique game context:

```
context = SHA-256(game_id || turn_number || action_type || parent_event_hash)
```

Co-signers must verify the context in `RANDOMNESS_REQUEST` matches the current game state before producing a partial response. A `TOPRF_PARTIAL` produced for an invalid or stale context is itself invalid.

Verifiers reject `RANDOMNESS_REVEAL` events whose context does not match the game state at the point of the corresponding `RANDOMNESS_REQUEST`.

### 8.8 Worked Example (n=4, t=3)

**Setup:** 4 players with indices `{1, 2, 3, 4}`. Threshold `t = floor(8/3) + 1 = 3`. Player 4 is offline.

**Signing set:** `S = {1, 2, 3}`

**Lagrange coefficients at 0** (mod group order `q`):

```
λ_1 = ((0-2)/(1-2)) * ((0-3)/(1-3))  =  (-2/-1) * (-3/-2)  =  2 * (3/2)  =  3
λ_2 = ((0-1)/(2-1)) * ((0-3)/(2-3))  =  (-1/1)  * (-3/-1)  = -1 *  3     = -3
λ_3 = ((0-1)/(3-1)) * ((0-2)/(3-2))  =  (-1/2)  * (-2/1)   =  1
```

*Division is modular inverse over the group order. Check: 3 + (-3) + 1 = 1 ✓*

**Reconstruction:**

```
C' = 3*C'_1 + (-3)*C'_2 + 1*C'_3
```

**Full flow:**

```
Player 1 generates x, computes B' = Hash_to_curve(x) + r*G
Player 1 publishes RANDOMNESS_REQUEST (commitment, B', context)

Player 1 computes C'_1 = s_1 * B', generates π_1, publishes TOPRF_PARTIAL
Player 2 computes C'_2 = s_2 * B', generates π_2, publishes TOPRF_PARTIAL
Player 3 computes C'_3 = s_3 * B', generates π_3, publishes TOPRF_PARTIAL
(Player 4 offline — not needed)

Player 1 verifies π_1, π_2, π_3 against S_1, S_2, S_3
Player 1 computes C' = 3*C'_1 - 3*C'_2 + 1*C'_3
Player 1 publishes RANDOMNESS_RESPONSE (C')

Player 1 computes C = C' - r*K
Player 1 publishes RANDOMNESS_REVEAL (x, r, C)

Anyone verifies:
  SHA-256(x) matches RANDOMNESS_REQUEST commitment  ✓
  C is a valid BDHKE unblinding of C' under K        ✓

seed = SHA-256(C.x_coordinate || context)
```

---

## 9. Private Game State

Players may maintain hidden state using SHA-256 commit-reveal pairs published as Nostr events.

### 9.1 Commit

```json
{
  "kind": 30007,
  "content": {
    "game_id": "<game_id>",
    "commitment": "<SHA-256(secret || nonce)>"
  },
  "tags": [["e", "<parent event id>"], ["d", "<game_id>"]]
}
```

The `nonce` must be uniformly random (minimum 16 bytes) to prevent preimage recovery via dictionary attack. The `secret` may be arbitrary game data — a hand of cards, a hidden unit position, a planned move.

### 9.2 Reveal

```json
{
  "kind": 30008,
  "content": {
    "game_id": "<game_id>",
    "secret": "<plaintext>",
    "nonce": "<hex>",
    "commit_event_id": "<event id of COMMIT>"
  },
  "tags": [["e", "<COMMIT event id>"], ["d", "<game_id>"]]
}
```

Verifiers check:
- `SHA-256(secret || nonce)` matches the `commitment` in the referenced `COMMIT` event
- The `COMMIT` event precedes this `REVEAL` in the DAG — a reveal without a prior commit is invalid

Random seeds from `RANDOMNESS_REVEAL` may be used as the basis for private draws that are themselves committed before the seed is known, allowing fully private and verifiable card dealing or similar mechanics.

---

## 10. Turn Timeout & Forfeit

Each game configures `turn_timeout_seconds` in `GAME_CREATE`. The clock begins from the `created_at` timestamp of the last event that required action from a specific player.

Timeout applies at every stage:

| Stage | Responsible Player | Consequence |
|-------|--------------------|-------------|
| Publishing `GAME_ACTION` | The player whose turn it is | Forfeit |
| Publishing `RANDOMNESS_REQUEST` | The player who needs randomness | Forfeit |
| Publishing `TOPRF_PARTIAL` | Each co-signer | That player forfeits (game may continue if remaining players still meet threshold) |
| Publishing `RANDOMNESS_REVEAL` | The requesting player | Forfeit |

When a forfeit condition is met, any peer may publish `GAME_END` citing the timed-out event ID and the offending player's pubkey. The game rule implementation determines what "forfeit" means for the specific game (loss, disqualification, substitution).

---

## 11. Threat Model

| Threat | Mitigation |
|--------|------------|
| Single player biases randomness | Threshold OPRF: biasing `C'` requires controlling `t` secret shares |
| Requesting player grinds for favorable `x` | Public `SHA-256(x)` commitment precedes any partial response; abandonment triggers forfeit |
| Co-signer produces invalid partial response | DLEQ proof is published alongside `C'_i`; invalid proofs are verifiably rejected |
| Token reused across game contexts | Context field `SHA-256(game_id || turn || action_type || parent_event_hash)` is part of the signing commitment |
| Player abandons after learning seed | Timeout + forfeit; outcome of revealed seed is recorded in `RANDOMNESS_REVEAL` on-chain |
| Coalition of `t-1` players colludes | Insufficient shares to reconstruct `k`; OPRF output is computationally indistinguishable from random |
| Coalition of `t` or more players colludes | Threshold does not prevent this; `t = floor(2n/3) + 1` makes this a strict Byzantine majority |
| Event ordering dispute | Parent hash chain is canonical; fork resolution by timestamp then event ID; forks are preserved as evidence |
| Forged game state | All events are Nostr-signed; state is derived deterministically from the auditable public event DAG |
| DKG participant publishes invalid shares | Share verification against Feldman commitments detects cheating; invalid `DKG_ROUND_2` is on-chain evidence |

---

## 12. Cryptographic Construction Reference

### Primitives

| Primitive | Specification |
|-----------|---------------|
| Elliptic curve | Secp256k1 (consistent with Nostr and Bitcoin) |
| Hash to curve | `Hash_to_curve` per [[RFC9380]](#RFC9380) using secp256k1 |
| Pedersen DKG | [[RFC9591]](#RFC9591), Section 4 |
| BDHKE | [[CashuNUT00]](#CashuNUT00) |
| DLEQ proofs | Chaum-Pedersen protocol [[ChaumPedersen93]](#ChaumPedersen93), non-interactive via Fiat-Shamir with domain separator `"NUTCHAIN_DLEQ_v1"`. Normative pseudocode in [[RFC9497]](#RFC9497) Section 2.2 |
| Threshold OPRF | [[JKKX17]](#JKKX17) |
| Event encryption | NIP-44 (for encrypted DKG shares) |
| General hashing | SHA-256 |

### Domain Separation

All hash operations in NutChain are domain-separated with a unique prefix string to prevent cross-protocol attacks:

| Context | Domain Separator |
|---------|-----------------|
| DLEQ challenge | `"NUTCHAIN_DLEQ_v1"` |
| Randomness context | `"NUTCHAIN_CTX_v1"` |
| Seed derivation | `"NUTCHAIN_SEED_v1"` |
| Multi-value derivation | `"NUTCHAIN_VAL_v1"` |

### Public Key Share Derivation

Public key shares `S_j` are computable by any verifier from the published DKG Round 1 commitments, without any private information:

```
S_j = Σ_i Σ_{k=0}^{t-1} C_{i,k} * j^k
```

This means DLEQ proofs in `TOPRF_PARTIAL` events are fully verifiable by any observer, not just the game participants.

---

## 13. References

### Academic Literature

**[ChaumPedersen93]** <a name="ChaumPedersen93"></a>
David Chaum and Torben Pryds Pedersen.
"Wallet Databases with Observers."
*CRYPTO 1992*, LNCS 740, pp. 89–105.
https://link.springer.com/chapter/10.1007/3-540-48071-4_7

Introduces the DLEQ sigma protocol (Section 8.4). Proves zero-knowledge by Jarecki et al. in [JKKX17]; made non-interactive via Fiat-Shamir.

---

**[JKKX17]** <a name="JKKX17"></a>
Stanislaw Jarecki, Aggelos Kiayias, Hugo Krawczyk, and Jiayu Xu.
"TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF."
*ACNS 2017*. Cryptology ePrint Archive, Paper 2017/363.
https://ia.cr/2017/363

Primary academic reference for the Threshold OPRF construction in Section 8. Introduces the T-OMDH (Threshold One-More Diffie-Hellman) hardness assumption and proves UC security of the one-round partial evaluation + Lagrange interpolation scheme. Achieves one exponentiation per co-signer, two per requester, regardless of group size.

---

**[JKR18]** <a name="JKR18"></a>
Stanislaw Jarecki, Hugo Krawczyk, and Jason Resch.
"Threshold Partially-Oblivious PRFs with Applications to Key Management."
Cryptology ePrint Archive, Paper 2018/733.
https://ia.cr/2018/733

Extends threshold OPRFs to the partially-oblivious setting, where a public input is mixed into the PRF evaluation. Relevant to the context-binding mechanism in Section 8.7, which incorporates a public `context` field into each randomness request.

---

### Standards and Specifications

**[RFC9497]** <a name="RFC9497"></a>
A. Davidson, A. Faz-Hernandez, N. Sullivan, C. A. Wood.
"Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups."
IRTF CFRG, December 2023.
https://www.rfc-editor.org/rfc/rfc9497

Normative reference for the single-signer VOPRF and the DLEQ proof construction (Section 2.2 of the RFC, referenced in Section 8.4 of this spec). The threshold extension is not covered by this RFC; see [JKKX17].

---

**[RFC9591]** <a name="RFC9591"></a>
D. Connolly, C. Komlo, I. Goldberg, C. A. Wood.
"The Flexible Round-Optimized Schnorr Threshold (FROST) Signature Scheme."
IRTF CFRG, June 2024.
https://www.rfc-editor.org/rfc/rfc9591

Reference for the Pedersen DKG protocol used in Sections 6.2 and 6.3.

---

**[RFC9380]** <a name="RFC9380"></a>
A. Faz-Hernandez, S. Scott, N. Sullivan, R. Wahby, C. Wood.
"Hashing to Elliptic Curves."
IRTF CFRG, August 2023.
https://www.rfc-editor.org/rfc/rfc9380

Specifies `Hash_to_curve` used in BDHKE blinding (Section 8.1).

---

**[CashuNUT00]** <a name="CashuNUT00"></a>
Cashu contributors.
"NUT-00: Notation, Utilization, and Terminology."
https://github.com/cashubtc/nuts/blob/main/00.md

Specifies the BDHKE scheme that forms the single-signer base of the DASoR protocol (Section 8.1).

---

**[CashuNUT12]** <a name="CashuNUT12"></a>
Cashu contributors.
"NUT-12: Offline ecash signature validation."
https://github.com/cashubtc/nuts/blob/main/12.md

Specifies DLEQ proofs for single-signer Cashu blind signatures — the single-server baseline from which the threshold construction in Section 8.4 is derived.

---

### Prior Art and Implementations

**[Fedimint]** <a name="Fedimint"></a>
Fedimint contributors.
"Fedimint: A Federated Chaumian Mint."
https://github.com/fedimint/fedimint

Production implementation of threshold blind signatures using Feldman secret sharing, DLEQ proofs, and Lagrange interpolation over secp256k1. The closest existing reference implementation to the DASoR protocol in Section 8.

---

### Note on Standardization Status

The threshold extension of OPRF — distributing the signing key across multiple parties via Feldman secret sharing and reconstructing via Lagrange interpolation — is described in [[JKKX17]](#JKKX17) and implemented in [[Fedimint]](#Fedimint), but does not yet have a finalized IETF RFC. [RFC9497] covers only the single-signer case. Implementers of the DASoR protocol should treat [[JKKX17]](#JKKX17) as the primary cryptographic reference and [[Fedimint]](#Fedimint) as the primary implementation reference for the threshold variant.
