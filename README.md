# NutChain Game Engine Specification

## 1. Overview & Design Goals

NutChain is a turn-based game engine that uses Nostr events as the substrate for all game data. Events are cryptographically signed, hash-referenced, and form a verifiable directed acyclic graph (DAG) that any party can replay to reconstruct authoritative game state.

The engine provides:

- **Verifiable, ordered game state** via a Nostr event DAG
- **Fully self-sovereign gameplay** — no trusted third party; the player set is the authority
- **Unbiasable randomness** via Cashu blinded signatures combined with FROST threshold Schnorr signing
- **Arbitrary game rules** expressed as a deterministic pure function over the event DAG
- **Private game state** via SHA-256 commit-reveal pairs

---

## 2. Actors

| Actor | Role |
|-------|------|
| **Players** | Participate in gameplay, DKG, and FROST signing rounds |
| **Game Rule Implementation** | A deterministic function `f(ordered_events) → game_state`, identified by hash at genesis |
| **Verifiers** | Any party that replays the event DAG to independently verify outcomes |

No external authority exists. The player set collectively acts as the signing authority for randomness.

---

## 3. Nostr Event Kinds

All events carry the following base fields:

| Field | Description |
|-------|-------------|
| `game_id` | Unique identifier for the game instance |
| `e` tag | Hash of the parent event (enforces ordering) |
| `pubkey` | Author's Nostr public key |
| `sig` | Nostr Schnorr signature over the event |

### Event Kind Registry

| Kind | Name | Description |
|------|------|-------------|
| `30000` | `GAME_CREATE` | Genesis event. Encodes rules hash, player pubkeys, and FROST `(t, n)` parameters |
| `30001` | `PLAYER_JOIN` | Player accepts game invite. References `GAME_CREATE` |
| `30010` | `DKG_ROUND_1` | Player publishes FROST DKG polynomial commitments |
| `30011` | `DKG_ROUND_2` | Player publishes encrypted key shares addressed to each peer |
| `30012` | `GAME_START` | Commits the aggregated FROST group public key `K`. Game begins upon publication |
| `30002` | `GAME_ACTION` | A player action. References its parent event to enforce turn ordering |
| `30003` | `RANDOMNESS_REQUEST` | Player publishes `SHA-256(x)` commitment, blinded message `B'`, and signing context |
| `30004` | `FROST_SIGN_ROUND_1` | Requesting player initiates FROST signing; publishes nonce commitments |
| `30013` | `FROST_SIGN_ROUND_2` | Each co-signing player publishes their partial signature |
| `30005` | `RANDOMNESS_RESPONSE` | Aggregated FROST Schnorr blind signature `C'` |
| `30006` | `RANDOMNESS_REVEAL` | Player reveals `x`, blinding factor `r`, and unblinded signature `C` |
| `30007` | `COMMIT` | Generic SHA-256 commitment for private game state |
| `30008` | `REVEAL` | Preimage reveal for a prior `COMMIT` event |
| `30009` | `GAME_END` | Final state assertion. References the full event chain |

---

## 4. Game Setup Phase

The setup phase follows a strict sequence before gameplay begins:

```
GAME_CREATE → PLAYER_JOIN (×n) → DKG_ROUND_1 (×n) → DKG_ROUND_2 (×n) → GAME_START
```

### 4.1 GAME_CREATE

The founding player publishes a `GAME_CREATE` event containing:

- `rules_hash` — SHA-256 hash of the game rule implementation. All clients must run a matching implementation.
- `players` — list of expected player Nostr public keys
- `frost_n` — total number of players in the signing group
- `frost_t` — signing threshold: `floor(2n/3) + 1` (Byzantine majority, consistent with Fedimint)
- `turn_timeout_seconds` — configurable per-game timeout after which an unresponsive player forfeits

### 4.2 Distributed Key Generation (DKG)

Players execute a two-round FROST DKG protocol. Both rounds are published as Nostr events, making the setup fully auditable and replayable by any verifier.

**Round 1 (`DKG_ROUND_1`):** Each player broadcasts their polynomial commitments.

**Round 2 (`DKG_ROUND_2`):** Each player publishes encrypted secret shares addressed to each peer, encrypted to the recipient's Nostr public key.

### 4.3 GAME_START

Once all DKG rounds are complete, any player publishes `GAME_START` containing:

- `group_pubkey` — the aggregated FROST group public key `K`
- Reference to all `DKG_ROUND_2` events

The group public key `K` is immutable for the lifetime of the game. No key changes are permitted after `GAME_START`.

---

## 5. Game State & Event DAG

### 5.1 Ordering

Every event (except `GAME_CREATE`) references the hash of its parent event via the `e` tag. This forms a hash-linked chain that enforces causal ordering and makes the event history tamper-evident.

### 5.2 State Derivation

Game state is derived by replaying all events in topological order through the game rule function:

```
state = f(event_0, event_1, ..., event_n)
```

This function is deterministic and pure. Given the same ordered event list, any implementation matching `rules_hash` will produce identical state.

### 5.3 Fork Resolution

If two events reference the same parent (a fork), the canonical event is determined by:

1. Earliest Nostr event timestamp
2. If timestamps are equal, lexicographically lowest event ID

---

## 6. Deterministic Authoritative Source of Randomness (DASoR)

The DASoR protocol ensures that neither any individual player nor any coalition below the threshold `t` can bias random outcomes. Randomness is a joint product of the requesting player's secret and the threshold signature of the player group.

### 6.1 Security Properties

| Property | Mechanism |
|----------|-----------|
| Authority cannot bias outcome | Blind signature — signers sign without knowing the player's secret `x` |
| Player cannot bias outcome | Player controls `x` but not the group signing key `k`; neither alone determines the output |
| Grinding is mitigated | Player commits to `SHA-256(x)` on Nostr before receiving the blind signature |
| Tokens are single-use | Each token is cryptographically bound to a unique game context |

### 6.2 Protocol Flow

```
1. Player generates secret x (uniformly random)

2. Player publishes RANDOMNESS_REQUEST:
     commitment = SHA-256(x)
     B'         = Hash_to_curve(x) + r*G     where r is a secret blinding factor
     context    = SHA-256(game_id || turn || action_type || parent_event_hash)

3. Requesting player publishes FROST_SIGN_ROUND_1:
     Nonce commitments from the requesting player
     Other players respond with FROST_SIGN_ROUND_2 (partial signatures over B' || context)
     The requesting player participates as a co-signer

4. Once t partial signatures are collected, requesting player aggregates them:
     C' = aggregated FROST Schnorr blind signature

5. Player publishes RANDOMNESS_RESPONSE containing C'

6. Player publishes RANDOMNESS_REVEAL:
     x  — the original secret
     r  — the blinding factor
     C  = C' - r*K   (unblinded signature)

7. Verification (anyone):
     Check SHA-256(x) matches the commitment in RANDOMNESS_REQUEST
     Check k * Hash_to_curve(x) == C  using group pubkey K

8. Random seed derivation:
     seed = SHA-256(C.x_coordinate)
```

### 6.3 Multi-Value Derivation

When a single game action requires multiple independent random values, they are derived from a single seed using a counter:

```
value_0 = SHA-256(seed || 0x00000000)
value_1 = SHA-256(seed || 0x00000001)
value_2 = SHA-256(seed || 0x00000002)
...
```

The number of values consumed is determined by the game rules and must be declared in the `RANDOMNESS_REQUEST` context field.

### 6.4 Anti-Grinding

- The commitment `SHA-256(x)` is published on Nostr before any blind signature is returned. A player wishing to grind must publicly submit multiple `RANDOMNESS_REQUEST` events, which is observable by all peers.
- Abandoning the protocol after publishing `RANDOMNESS_REQUEST` — for example, to avoid an unfavorable outcome — triggers the **timeout + forfeit** rule (see Section 7).
- Game rule implementations may enforce additional rate limits on `RANDOMNESS_REQUEST` events as an application-layer control.

### 6.5 Context Binding

Each token is bound to a unique context:

```
context = SHA-256(game_id || turn || action_type || parent_event_hash)
```

A token issued for one game context cannot be replayed or applied to any other context. Verifiers reject `RANDOMNESS_REVEAL` events whose context does not match the current game state.

---

## 7. Turn Timeout & Forfeit

If a player fails to advance the game within `turn_timeout_seconds` (set in `GAME_CREATE`) after it becomes their turn, the following applies:

- Any peer may publish a `GAME_END` event citing timeout
- The non-responsive player forfeits the game
- This applies at any stage: during a player's action, during FROST signing rounds, or after receiving a randomness token

The timeout is measured from the timestamp of the last valid event that required the player to act.

---

## 8. Private Game State

Players may maintain private state using SHA-256 commit-reveal pairs.

### 8.1 Commit

```
COMMIT event:
  commitment = SHA-256(secret || nonce)
```

The `nonce` must be uniformly random to prevent preimage attacks via dictionary lookup.

### 8.2 Reveal

```
REVEAL event:
  secret
  nonce
  references: COMMIT event hash
```

Verifiers check that `SHA-256(secret || nonce)` matches the commitment. The `COMMIT` event must precede its `REVEAL` in the event DAG; a reveal without a prior commit is invalid.

Random seeds used for private draws remain hidden until `RANDOMNESS_REVEAL` is published, at which point the full derivation is auditable.

---

## 9. Threat Model

| Threat | Mitigation |
|--------|------------|
| Single player biases randomness | FROST threshold requires `t = floor(2n/3) + 1` colluders |
| Player grinds for favorable `x` | Public commitment before blind sig; abandonment triggers forfeit |
| Token reuse across game contexts | Context field binds token to `(game_id, turn, action_type, parent_event_hash)` |
| Player abandons after receiving token | Timeout + forfeit; duration configurable in `GAME_CREATE` |
| Event ordering dispute | Parent hash chain is canonical; fork resolution by timestamp then event ID |
| Signing key compromise | Blast radius limited to threshold colluders; key committed at `GAME_START` and immutable |
| Requester learns outcome before co-signers | Blinding hides `x` from all signers including the requester during signing |
| Forged game state | All events are Nostr-signed; state is derived deterministically from the public event DAG |

---

## 10. FROST Implementation Notes

NutChain uses FROST (Flexible Round-Optimized Schnorr Threshold) signatures as specified in [IETF RFC 9591](https://www.rfc-editor.org/rfc/rfc9591).

Key parameters:

- **Threshold:** `t = floor(2n/3) + 1`
- **Group:** Secp256k1 (consistent with Nostr)
- **DKG:** Pedersen DKG as described in the FROST RFC
- **Signing context:** All FROST signing operations are domain-separated by the `context` field from the `RANDOMNESS_REQUEST` event

The requesting player acts as the signature aggregator and is a valid co-signer. There is no designated coordinator role; the player who needs randomness drives the protocol.
