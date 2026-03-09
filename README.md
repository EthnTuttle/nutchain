# NutChain Game Engine Draft Design Specification

## 1. Overview & Design Goals

NutChain is a turn-based game engine that uses Nostr events as the substrate for all game data. Events are cryptographically signed, hash-referenced, and form a verifiable linear chain that any party can replay to reconstruct authoritative game state.

The engine provides:

- **Verifiable, ordered game state** via a hash-linked Nostr event chain
- **Fully self-sovereign gameplay** — no trusted third party; the player set is the authority
- **Unbiasable randomness** via Cashu's BDHKE blinding scheme extended to a Threshold OPRF across the player set
- **Arbitrary game rules** expressed as a deterministic pure function over the event chain
- **Private game state** via SHA-256 commit-reveal pairs

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **BDHKE** | Blind Diffie-Hellman Key Exchange. Cashu's blinding scheme: `B_ = hash_to_curve(x) + r*G`, where `r` is a secret scalar and `r*G` is the blinding point, `C_ = k*B_`, `C = C_ - r*K`. Uses the `hash_to_curve` function from [[CashuNUT00]](#CashuNUT00) (try-and-increment with domain separator `b"Secp256k1_HashToCurve_Cashu_"`, counter encoded as little-endian uint32) |
| **Threshold OPRF** | Threshold Oblivious Pseudorandom Function. Distributes the BDHKE signing key `k` across `n` parties requiring `t` to cooperate to produce a valid response |
| **DLEQ Proof** | Discrete Log Equality proof. Proves `log_G(S_i) == log_{B_}(C_i)` without revealing the secret share `s_i` |
| **ChillDKG** | A distributed key generation protocol for FROST [[ChillDKG]](#ChillDKG), incorporating EncPedPop for encrypted share delivery via ECDH and CertEq for consensus via signature certificates. No trusted dealer required |
| **CertEq** | Certificate-based equality check protocol. Each participant signs the DKG session transcript; the collection of all `n` valid signatures forms a *success certificate* proving agreement |
| **DASoR** | Deterministic Authoritative Source of Randomness. The full protocol by which unbiasable random seeds are produced |
| **Signing set** | The specific subset `S` of `t` players who respond to a given `RANDOMNESS_REQUEST` |
| **Event chain** | The hash-linked linear sequence of Nostr events that encodes all game state |
| **Group key** | The aggregated public key `K` derived from all players' DKG commitments |
| **Sequence number** | A monotonically increasing counter assigned to each event in the chain, used to establish absolute ordering and bind randomness to a specific game state |

---

## 3. Actors

| Actor | Role |
|-------|------|
| **Players** | Participate in gameplay, DKG, and Threshold OPRF signing rounds |
| **Game Creator** | The player who publishes `GAME_CREATE`. Also serves as the DKG coordinator (Section 6.3) |
| **Game Rule Implementation** | A deterministic pure function `f(ordered_events) -> game_state`, identified by hash at genesis |
| **Verifiers** | Any party that replays the event chain to independently verify game state and randomness proofs |

No external authority exists. The player set collectively holds the group signing key and acts as the randomness authority.

---

## 4. Nostr Event Schema

### 4.1 Base Event Fields

Every NutChain event is a standard Nostr event. Per NIP-01, the `content` field is an arbitrary string. All structured data is serialized as stringified JSON within `content`. A future revision may migrate fields to Nostr tags for improved relay indexing.

| Field | Description |
|-------|-------------|
| `game_id` | Unique identifier for the game instance. A client-generated random identifier (e.g., 32-byte hex string) set in the `GAME_CREATE` `d` tag and referenced by all subsequent events |
| `e` tag | Hash of the previous event in the chain. Enforces absolute ordering |
| `pubkey` | Author's Nostr public key |
| `sig` | Nostr Schnorr signature over the event |
| `seq` | Sequence number within the `content` JSON. Monotonically increasing integer starting at 0 for `GAME_CREATE` |

### 4.2 Event Kind Registry

These kind numbers are provisional and occupy an unregistered sub-range of Nostr's addressable event space (`30000-39999`). Per NIP-01, addressable events are replaceable: a relay will only store the latest event for a given `kind + pubkey + d` combination. Since each player has a unique `pubkey`, events from different players do not collide. For events where a single player may publish multiple events of the same kind within one game (e.g., `TOPRF_PARTIAL` across different rounds), the `d` tag must include a disambiguator (e.g., `game_id:request_event_id`) to prevent relay-level replacement. A formal NIP may be proposed if this protocol is adopted more broadly.

| Kind | Name | Phase | Description |
|------|------|-------|-------------|
| `30800` | `GAME_CREATE` | Setup | Genesis event. Encodes rules hash, player pubkeys, threshold parameters, and timeout |
| `30801` | `PLAYER_JOIN` | Setup | Player requests to join the game. References `GAME_CREATE` |
| `30802` | `PLAYER_JOIN_ACK` | Setup | Game creator acknowledges a player's join request |
| `30803` | `DKG_ROUND_1` | Setup | Player publishes VSS commitments, proof of possession, encrypted shares, and ECDH ephemeral nonce |
| `30804` | `DKG_ROUND_2` | Setup | Coordinator publishes aggregated commitments and per-participant encrypted share sums |
| `30805` | `DKG_CERTIFY` | Setup | Player publishes CertEq signature over the session transcript |
| `30806` | `DKG_BLAME` | Setup | Player publishes cryptographic evidence of DKG misbehavior by a peer |
| `30807` | `GAME_START` | Setup | Commits the group public key `K` and the success certificate. Game begins upon publication |
| `30808` | `GAME_ACTION` | Gameplay | A player action. Contains game-specific data alongside protocol fields |
| `30809` | `RANDOMNESS_REQUEST` | Gameplay | Player commits to `SHA-256(x)`, publishes blinded message `B_` and signing context |
| `30810` | `TOPRF_PARTIAL` | Gameplay | A co-signer's partial evaluation `C_i = s_i * B_` and DLEQ proof `pi_i` |
| `30811` | `RANDOMNESS_REVEAL` | Gameplay | Player reveals `x`, blinding factor `r`, aggregated blind signature `C_`, and unblinded signature `C` |
| `30812` | `COMMIT` | Gameplay | SHA-256 commitment for private game state |
| `30813` | `REVEAL` | Gameplay | Preimage reveal for a prior `COMMIT` event |
| `30814` | `GAME_END` | Teardown | Final state assertion. References the full event chain |

### 4.3 Serialization and Encoding

All hash constructions in NutChain must produce identical output across implementations. The following encoding rules apply to every SHA-256 input in this specification:

| Data Type | Encoding |
|-----------|----------|
| Domain separators (e.g., `"NUTCHAIN_DLEQ_v1"`) | UTF-8 bytes, no null terminator |
| `game_id` | Raw bytes (32 bytes if generated as 32 random bytes; if hex-encoded in JSON, decode to 32 bytes before hashing) |
| `seq` | Big-endian uint32 (4 bytes) |
| `action_type` | UTF-8 bytes, length-prefixed with big-endian uint16 (2 bytes) |
| `prev_event_hash` | Raw bytes (32 bytes, the SHA-256 event ID) |
| Curve points (e.g., `G`, `B_`, `S_i`, `C_i`) | SEC1 compressed encoding (33 bytes: `02`/`03` prefix + 32-byte x-coordinate) |
| Scalars (e.g., DLEQ challenge `e`, response `s`) | Big-endian unsigned 256-bit integer (32 bytes) |
| `C.x_coordinate` (in seed derivation) | Big-endian unsigned 256-bit integer (32 bytes) |
| Counter values (e.g., in value derivation KDF) | Big-endian uint32 (4 bytes) |
| `x` (randomness secret) | Raw bytes (32 bytes from CSPRNG). Passed directly to `hash_to_curve` per [[CashuNUT00]](#CashuNUT00) as a byte sequence, not hex-encoded |

**Concatenation:** Fields are concatenated directly (`||`) with no delimiters. Fixed-length fields (domain separators at known lengths, 32-byte hashes, 33-byte points, 4-byte integers) are self-delimiting. The only variable-length field used in hash inputs is `action_type`, which is length-prefixed as specified above.

**Hash construction reference table:**

| Construction | Input format |
|--------------|-------------|
| Context | `SHA-256(utf8("NUTCHAIN_CTX_v1") \|\| game_id[32] \|\| seq[4] \|\| len(action_type)[2] \|\| utf8(action_type) \|\| prev_event_hash[32])` |
| Seed | `SHA-256(utf8("NUTCHAIN_SEED_v1") \|\| C.x[32] \|\| context[32])` |
| Value derivation | `SHA-256(utf8("NUTCHAIN_VAL_v1") \|\| seed[32] \|\| counter[4])` |
| DLEQ challenge | `SHA-256(utf8("NUTCHAIN_DLEQ_v1") \|\| G[33] \|\| B_[33] \|\| S_i[33] \|\| C_i[33] \|\| A[33] \|\| Z[33])` |
| Commit-reveal | `SHA-256(nonce[16+] \|\| len(secret)[2] \|\| utf8(secret))` |

Bracketed numbers indicate byte widths. `[16+]` means minimum 16 bytes.

### 4.4 Relay Requirements

NutChain relies on Nostr relays for event transport but does not trust relays for correctness. The hash-linked chain ensures tamper-evidence regardless of relay behavior.

**Common relay:** All players in a game session must use the relays specified in the `relays` field of `GAME_CREATE`. Players may additionally publish to other relays for redundancy, but all game events must be published to at least one of the specified relays.

**Local event store:** Each client must maintain a local event store as the canonical view of the game chain. Relays serve as a transport layer, not an authority. If a relay drops or reorders events, clients reconstruct the chain from the hash links and sequence numbers.

**Addressable event handling:** Since NutChain events use addressable event kinds (`30000-39999`), relays may replace older events with newer ones sharing the same `kind + pubkey + d` combination. The `d` tag disambiguators specified in this document (e.g., `game_id:seq`, `game_id:request_event_id`) are designed to prevent unintended replacement. Clients should fetch events by `d` tag + `kind` and verify hash-chain integrity locally.

**Relay failure:** A relay going offline or refusing to store events halts game progress but does not compromise game integrity. Players can migrate to an alternative relay and re-publish their local event stores. The hash chain ensures consistency even across relay migrations.

---

## 5. Game Lifecycle

```
 SETUP PHASE
 ────────────────────────────────────────────────────────────
 GAME_CREATE                                    (seq 0)
   ├── PLAYER_JOIN x (n-1)                     (readiness confirmation)
   │     └── PLAYER_JOIN_ACK x (n-1)           (creator acknowledges)
   ├── DKG_ROUND_1 x n                         (EncPedPop: commitments + encrypted shares)
   │     └── DKG_ROUND_2                        (coordinator aggregation)
   │           └── DKG_CERTIFY x n              (CertEq signatures)
   │                 └── GAME_START             (success certificate + group key K)

 GAMEPLAY PHASE (repeating)
 ────────────────────────────────────────────────────────────
 GAME_ACTION
   └── (if randomness needed)
         RANDOMNESS_REQUEST
           └── TOPRF_PARTIAL x t               (co-signers respond)
                 └── RANDOMNESS_REVEAL          (requester aggregates + reveals)
                       └── GAME_ACTION          (next turn)

 TEARDOWN
 ────────────────────────────────────────────────────────────
 GAME_END
```

*Note: The sequence numbers and ordering shown above are illustrative. PLAYER_JOIN and PLAYER_JOIN_ACK events may interleave (e.g., join-ack-join-ack rather than all joins then all acks). The only requirement is that each event's `seq` equals its predecessor's `seq + 1` in the hash-linked chain.*

---

## 6. Game Setup Phase

### 6.1 GAME_CREATE

The founding player (game creator) generates a unique `game_id` (e.g., 32 random bytes, hex-encoded) and publishes the genesis event. This `game_id` is used as the `d` tag value on all events in the game, enabling relay queries by `game_id`. All subsequent events reference the previous event's hash via the `e` tag, forming a strict linear chain.

```json
{
  "kind": 30800,
  "content": "{\"seq\": 0, \"protocol_version\": \"1.0\", \"rules_hash\": \"<sha256 of game rule implementation>\", \"players\": [\"<nostr pubkey 0>\", \"<nostr pubkey 1>\", \"<nostr pubkey n-1>\"], \"frost_t\": 3, \"turn_timeout_seconds\": 300, \"relays\": [\"wss://relay.example.com\"]}",
  "tags": [["d", "<game_id>"]]
}
```

- `seq` — Sequence number. Always `0` for `GAME_CREATE`.
- `protocol_version` — NutChain protocol version string. Clients must reject games with an unrecognized protocol version. The current version is `"1.0"`.
- `rules_hash` — SHA-256 of the game rule implementation. All clients must run a matching implementation or their state derivations are invalid.
- `players` — Ordered array of Nostr public keys. The array length determines `n`. Player indices are 0-based, corresponding to array position.
- `frost_t` — signing threshold: `floor(2n/3) + 1` (Byzantine majority, consistent with Fedimint). For `n=4`, `t=3`. For `n=3`, `t=3`. For `n=7`, `t=5`.
- `turn_timeout_seconds` — after this duration without a required event from a player, any peer may declare forfeit.
- `relays` — ordered array of relay WebSocket URLs (e.g., `["wss://relay.example.com"]`). All players should publish to and subscribe from these relays. The first relay in the array is the primary; others are fallbacks.

#### Threshold and Fault Tolerance

The threshold formula `t = floor(2n/3) + 1` determines how many players must cooperate for randomness generation and how many can be offline without blocking the game:

| Players (n) | Threshold (t) | Fault tolerance (n - t) | Notes |
|-------------|---------------|-------------------------|-------|
| 2 | 2 | 0 | Unanimity — either player can block randomness |
| 3 | 3 | 0 | Unanimity — same limitation |
| 4 | 3 | 1 | **Minimum recommended for fault tolerance** |
| 5 | 4 | 1 | |
| 7 | 5 | 2 | |
| 10 | 7 | 3 | |

Games with `n < 4` operate under unanimity: any single player going offline blocks all randomness generation. The timeout/forfeit mechanism (Section 10) provides liveness in these cases, but it cannot prevent a losing player from forcing a forfeit rather than losing gracefully. **Minimum recommended `n` for meaningful fault tolerance is 4.**

### 6.2 PLAYER_JOIN and PLAYER_JOIN_ACK

The player list is fixed at `GAME_CREATE` time. The `PLAYER_JOIN` / `PLAYER_JOIN_ACK` flow serves as a **readiness confirmation**, not player discovery. It ensures each player is online, has the correct game parameters, and is prepared to enter DKG.

Each player listed in the `players` array publishes a `PLAYER_JOIN` event to signal their readiness to participate. The game creator then publishes a `PLAYER_JOIN_ACK` for each joining player to confirm acceptance. This ACK step allows the game creator to gate participation — a player whose `PLAYER_JOIN` is not acknowledged cannot proceed to DKG.

#### PLAYER_JOIN Event Schema

```json
{
  "kind": 30801,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"player_index\": 1}",
  "tags": [["e", "<GAME_CREATE event id>"], ["d", "<game_id>"]]
}
```

- `player_index` — The player's 0-based index in the `players` array from `GAME_CREATE`.

#### PLAYER_JOIN_ACK Event Schema

```json
{
  "kind": 30802,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"player_index\": 1, \"player_join_event_id\": \"<event id of PLAYER_JOIN>\"}",
  "tags": [["e", "<PLAYER_JOIN event id>"], ["d", "<game_id>:<player_index>"]]
}
```

The `d` tag uses a compound key (`game_id:player_index`) to prevent relay-level replacement when the game creator acknowledges multiple players.

The game creator's own participation is implicit in publishing `GAME_CREATE` — no `PLAYER_JOIN` or `PLAYER_JOIN_ACK` is required for the game creator (player index 0). DKG proceeds only after all remaining players have been acknowledged.

### 6.3 Distributed Key Generation (ChillDKG)

NutChain uses the ChillDKG protocol [[ChillDKG]](#ChillDKG) for distributed key generation. ChillDKG is a standalone DKG protocol that requires no trusted dealer, no external secure channels, and no external consensus mechanism. It is built from three components:

1. **SimplPedPop** — Feldman VSS with proofs of possession (Schnorr signatures on player index)
2. **EncPedPop** — Wraps SimplPedPop with ephemeral-static ECDH encryption for secret share delivery
3. **CertEq** — Equality check via signature certificates ensuring all players agree on the DKG transcript

Each player holds a long-term host key pair (their Nostr key pair). The host secret key serves as both the ECDH decryption key for encrypted share delivery and the signing key for CertEq certificates.

#### Key Reuse Note

NutChain uses each player's Nostr key pair for three purposes: (1) Nostr event signing (BIP-340 Schnorr), (2) ECDH decryption for DKG share delivery, and (3) CertEq certificate signing. ChillDKG itself considers dual use of host keys (ECDH + CertEq). The additional use for Nostr event signing is consistent with existing Nostr ecosystem practice — NIP-44, for example, co-deploys BIP-340 Schnorr signing and ECDH over the same key pair. For a game engine, this is considered acceptable.

The **game creator** acts as the DKG coordinator for Round 2 aggregation. This role does not grant the coordinator any cryptographic advantage — the coordinator sees only encrypted shares and public commitments, and all aggregation results are independently verifiable by every participant.

#### Security Note

ChillDKG's security proof [[CGRS23]](#CGRS23) establishes composability with FROST Schnorr signing. The ChillDKG BIP explicitly states that ChillDKG "must not be combined with other threshold cryptographic schemes ... without careful further consideration." NutChain uses the same DKG output — Feldman VSS shares of a group scalar over secp256k1 — for Threshold OPRF rather than FROST signing. While the DKG output is structurally identical (secret shares of a polynomial over the same curve), the composability argument from [[CGRS23]](#CGRS23) does not directly transfer to the OPRF setting. This is a **known limitation**. NutChain is a game engine, not a custody protocol — no funds are at risk from the OPRF output. If usage grows and stakes increase, a formal security analysis of ChillDKG composed with Threshold OPRF should be pursued.

#### DKG Round 1 (EncPedPop Participant Broadcast)

Each player `i` independently generates a random polynomial `f_i(x)` of degree `t-1` over the scalar field:

```
f_i(x) = a_{i,0} + a_{i,1}*x + ... + a_{i,t-1}*x^{t-1}
```

The constant term `a_{i,0}` becomes player `i`'s contribution to the group secret. Player `i` computes:

- **Feldman VSS commitments:** `com_{i,k} = a_{i,k} * G` for `k = 0..t-1`
- **Proof of possession:** A BIP-340 Schnorr signature on message `i` with secret key `a_{i,0}`, preventing rogue-key attacks
- **Ephemeral ECDH nonce:** A fresh key pair `(ek_i, EK_i)` for encrypting secret shares
- **Encrypted shares:** For each peer `j`, the VSS share `f_i(j+1)` encrypted via ECDH between `ek_i` and `j`'s host public key, producing a shared pad `pad_{ij}`. The encrypted share is `f_i(j+1) + pad_{ij}`

All of this is published in a single `DKG_ROUND_1` event:

```json
{
  "kind": 30803,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"player_index\": 0, \"commitments\": [\"<hex com_{i,0}>\", \"<hex com_{i,1}>\"], \"proof_of_possession\": \"<hex BIP-340 signature>\", \"ecdh_pubkey\": \"<hex EK_i>\", \"encrypted_shares\": [{\"recipient_index\": 1, \"share\": \"<hex encrypted f_i(2)>\"}, {\"recipient_index\": 2, \"share\": \"<hex encrypted f_i(3)>\"}]}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>"]]
}
```

#### DKG Round 2 (Coordinator Aggregation)

The game creator acts as the coordinator. The coordinator collects all `n` `DKG_ROUND_1` events and aggregates:

- **Concatenated first commitments:** `coms_to_secrets = (com_{0,0}, ..., com_{n-1,0})`
- **Summed non-constant commitments:** Component-wise sum of `com_{i,k}` for `k = 1..t-1` across all `i`
- **Per-participant encrypted share sums:** For each participant `j`, the sum of all encrypted shares intended for `j`

The coordinator publishes a `DKG_ROUND_2` event:

```json
{
  "kind": 30804,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"coms_to_secrets\": [\"<hex com_{0,0}>\", \"<hex com_{1,0}>\", \"<hex com_{2,0}>\", \"<hex com_{3,0}>\"], \"sum_coms_nonconst\": [\"<hex sum of k=1 terms>\"], \"encrypted_share_sums\": [{\"recipient_index\": 0, \"enc_secshare\": \"<hex>\"}, {\"recipient_index\": 1, \"enc_secshare\": \"<hex>\"}, {\"recipient_index\": 2, \"enc_secshare\": \"<hex>\"}, {\"recipient_index\": 3, \"enc_secshare\": \"<hex>\"}], \"proofs_of_possession\": [\"<hex pop_0>\", \"<hex pop_1>\", \"<hex pop_2>\", \"<hex pop_3>\"], \"ecdh_pubkeys\": [\"<hex EK_0>\", \"<hex EK_1>\", \"<hex EK_2>\", \"<hex EK_3>\"]}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>"]]
}
```

Upon receiving `DKG_ROUND_2`, each player `j`:

**Verifies** every proof of possession `pop_i` using message `i` and public key `coms_to_secrets[i]`. If any is invalid, abort and blame that player.

**Derives** all ECDH pads `pad_{ij}` using the ephemeral public keys `EK_i` and their own host secret key, then decrypts their secret share:
```
secshare_j = enc_secshare_j - (pad_{0j} + pad_{1j} + ... + pad_{(n-1)j})
```

Each pad `pad_{ij}` is derived from the ECDH shared secret between sender `i`'s ephemeral key and recipient `j`'s host key, following ChillDKG's EncPedPop construction:

```
enc_context = t[4] || EK_0[33] || EK_1[33] || ... || EK_{n-1}[33]

For i != j (cross-participant):
  ecdh_input = ECDH(ek_i, HK_j).x[32]    (sender uses ephemeral seckey; recipient uses host seckey)
             || EK_i[33] || HK_j[33]       (sender pubnonce then recipient host pubkey)
             || j[4]                        (recipient index, big-endian uint32)
             || enc_context
  pad_{ij}   = tagged_hash("BIP DKG/encpedpop ecdh", ecdh_input) mod group_order

For i == j (self-encryption):
  self_input = HK_i_secret[32]             (player i's host secret key)
             || EK_i[33]                   (player i's ephemeral pubkey)
             || i[4]                        (own index, big-endian uint32)
             || enc_context
  pad_{ii}   = tagged_hash("BIP DKG/encaps_multi self_pad", self_input) mod group_order
```

Where `tagged_hash(tag, msg) = SHA-256(SHA-256(tag) || SHA-256(tag) || msg)` per BIP-340, `ECDH(sk, PK).x` is the x-coordinate of `sk * PK`, and `group_order` is the secp256k1 scalar field order. Encrypted shares are additive one-time pads over the scalar field: `enc_share_{ij} = f_i(j+1) + pad_{ij} mod group_order`.

**Reconstructs** the full summed VSS commitment:
```
sum_coms[0] = Sigma_i coms_to_secrets[i]
sum_coms[k] = sum_coms_nonconst[k-1]   for k = 1..t-1
```

**Verifies** their secret share against the summed commitments:
```
secshare_j * G == Sigma_{k=0}^{t-1} sum_coms[k] * (j+1)^k
```
If verification fails, the player requests individual encrypted shares from the coordinator to identify the misbehaving peer.

**Derives** the group public key:
```
K = sum_coms[0]
```

**Derives** all public key shares (computable by anyone):
```
S_j = Sigma_{k=0}^{t-1} sum_coms[k] * (j+1)^k
```

#### DKG Certification (CertEq)

Each player constructs the session transcript — a deterministic serialization of all DKG protocol data including the summed commitments, all ECDH public keys, and all encrypted share sums — and signs it with their host secret key. The BIP-340 Schnorr signature is computed over the full transcript byte string (format specified below). The `transcript_hash` field is SHA-256 of that byte string, published for convenient on-chain comparison without transmitting the full transcript in every event.

Each player publishes a `DKG_CERTIFY` event:

```json
{
  "kind": 30805,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"player_index\": 0, \"transcript_hash\": \"<hex SHA-256 of session transcript>\", \"certeq_signature\": \"<hex BIP-340 signature over full transcript bytes>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>"]]
}
```

A player finalizes the DKG when they have collected valid CertEq signatures from all `n` players. This collection of `n` signatures constitutes the **success certificate** — proof that all players agree on the DKG outcome.

**Session transcript format:**

The session transcript is a deterministic byte sequence that all players must compute identically. NutChain follows the ChillDKG [[ChillDKG]](#ChillDKG) `eq_input` construction from EncPedPop:

```
transcript = t[4]
          || sum_coms[0][33] || sum_coms[1][33] || ... || sum_coms[t-1][33]
          || EK_0[33] || EK_1[33] || ... || EK_{n-1}[33]
          || enc_secshare_0[32] || enc_secshare_1[32] || ... || enc_secshare_{n-1}[32]
```

Where:
- `t` — threshold, encoded as big-endian uint32 (4 bytes)
- `sum_coms[k]` — the full summed VSS commitment vector, SEC1 compressed (33 bytes each), in order `k = 0..t-1`. `sum_coms[0]` is the sum of all `coms_to_secrets[i]` (i.e., the group public key `K` before any Taproot tweak)
- `EK_i` — ECDH ephemeral public keys (SEC1 compressed, 33 bytes each), in player index order `i = 0..n-1`
- `enc_secshare_i` — encrypted secret share sums for each player (32 bytes each, scalar mod group order), in player index order `i = 0..n-1`

All fields are concatenated directly with no delimiters. The CertEq signature is a BIP-340 Schnorr signature with the player's host secret key over this transcript byte string. BIP-340 Schnorr internally applies a tagged hash to the message, so no additional hashing of the transcript is required before signing.

#### 6.3.1 DKG Failure and Blame

If a player detects misbehavior during the DKG process, they may publish a `DKG_BLAME` event with cryptographic evidence identifying the misbehaving peer. This provides on-chain accountability for DKG failures.

```json
{
  "kind": 30806,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"blaming_pubkey\": \"<nostr pubkey of blaming player>\", \"blamed_pubkey\": \"<nostr pubkey of blamed player>\", \"reason\": \"<invalid_pop|invalid_share|timeout>\", \"evidence\": <JSON object with blame-specific data>}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<blamed_pubkey>"]]
}
```

- `blaming_pubkey` — The Nostr public key of the player publishing the blame event (must match the event's `pubkey`).
- `blamed_pubkey` — The Nostr public key of the player accused of misbehavior.
- `reason` — One of:
  - `"invalid_pop"` — The blamed player's proof of possession failed verification. Evidence should include the invalid `pop` and the corresponding `com_{i,0}`.
  - `"invalid_share"` — The blamed player's encrypted share, when decrypted and verified against the Feldman commitments, failed the VSS check. Evidence should include the decrypted share, the ECDH pad derivation inputs, and the relevant commitments.
  - `"timeout"` — The blamed player failed to publish a required DKG event within `turn_timeout_seconds`.
- `evidence` — A JSON object containing the cryptographic data supporting the blame claim. The specific fields depend on the `reason`.

`DKG_BLAME` events are informational. They provide public accountability and allow other players to independently verify the blame claim. The game is considered aborted if `GAME_START` is not published; players may choose to start a new game excluding the misbehaving peer.

### 6.4 GAME_START

The game creator publishes `GAME_START` once the success certificate is complete:

```json
{
  "kind": 30807,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"group_pubkey\": \"<hex K>\", \"success_certificate\": [\"<hex certeq_sig_0>\", \"<hex certeq_sig_1>\", \"<hex certeq_sig_2>\", \"<hex certeq_sig_3>\"], \"transcript_hash\": \"<hex SHA-256 of session transcript>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>"]]
}
```

`K` is immutable for the lifetime of the game. No key changes are permitted after `GAME_START` is published. Game rules begin applying to events published after this point.

Any verifier can validate the success certificate by checking each CertEq signature against the corresponding player's host public key and the transcript hash.

---

## 7. Game State & Event Chain

### 7.1 Ordering

NutChain uses a strict linear ordering of events. Every event (except `GAME_CREATE`) references the hash of the immediately preceding event via the `e` tag, forming a hash-linked chain. Each event also carries a `seq` number in its content — a monotonically increasing integer starting at 0 for `GAME_CREATE`.

Because each event commits to its predecessor's hash, the full history is tamper-evident: altering any event invalidates all subsequent events. There is exactly one valid next event at any point in the chain — forks are not possible under correct operation, and any event that does not reference the current chain head is invalid.

### 7.2 State Derivation

Game state is derived by replaying all valid events in sequence order through the game rule function:

```
state_n = f(event_0, event_1, ..., event_n)
```

This function is deterministic and pure. Any implementation whose SHA-256 matches `rules_hash` from `GAME_CREATE` will produce identical state from identical input. Clients that cannot match `rules_hash` must not participate.

### 7.3 Sequence Number Validation

Each event's `seq` must equal the previous event's `seq + 1`. Events with out-of-sequence numbers are invalid. The `seq` field provides a simple mechanism for detecting gaps or duplicates independently of the hash chain.

### 7.4 Protocol vs. Game Rule Boundary

The NutChain engine and the game rule function have distinct responsibilities:

**NutChain engine** validates all protocol-level events: DKG rounds, CertEq signatures, TOPRF_PARTIAL proofs, RANDOMNESS_REQUEST/REVEAL verification, COMMIT/REVEAL hash checks, sequence numbers, hash-chain integrity, and timeout enforcement.

**Game rule function** `f()` receives only game-level events: `GAME_ACTION`, `COMMIT`, `REVEAL`, and derived random seeds (post-verification). The game rule function does not see or validate raw cryptographic protocol events (`DKG_ROUND_1`, `TOPRF_PARTIAL`, etc.). The engine passes the verified randomness seed to the game rule function, which uses the deterministic KDF (Section 8.5) to derive values.

This separation ensures game rule implementations are not coupled to the NutChain protocol version. A game rule function depends only on the game-level event interface, not on the underlying cryptographic machinery.

---

## 8. Deterministic Authoritative Source of Randomness (DASoR)

The DASoR protocol produces random seeds that are unbiasable by any individual player and by any coalition of fewer than `t` players. The random seed is a joint product of the requesting player's secret `x` and the group signing key `k`, where neither party can compute the result without the other's contribution.

Each turn that requires randomness produces exactly one seed via a single `RANDOMNESS_REQUEST`. The game rule function derives all needed random values from that seed using a deterministic counter-based KDF (see Section 8.5).

### 8.1 Cryptographic Primitives

**BDHKE (Cashu):**

The base single-signer scheme, using `hash_to_curve` as defined in [[CashuNUT00]](#CashuNUT00). The `hash_to_curve` function uses the try-and-increment method with domain separator `b"Secp256k1_HashToCurve_Cashu_"` (byte string) and a counter encoded as little-endian uint32, incrementing from 0 until a valid curve point is found.

This specification adopts Cashu's underscore notation for blinded values:

```
Blinding:   B_ = hash_to_curve(x) + r*G
Signing:    C_ = k * B_
Unblinding: C  = C_ - r*K  =  k * hash_to_curve(x)
Identity:   C == k * hash_to_curve(x)  where K = k*G
```

`C` is a deterministic function of `x` and `k`. Neither `x` (known only to the player) nor `k` (held as shares across players) alone determines the output. Note that the identity line describes the mathematical relationship, not a verification procedure — no single party knows `k`. In the threshold setting, correctness is verified via DLEQ proofs on each partial evaluation (see Section 8.4).

**Threshold OPRF:**

The multi-signer extension. Each player `i` holds a secret share `s_i` of the group key `k`. To compute `k * B_` without any single player knowing `k`:

1. Each co-signer `i` computes a partial evaluation: `C_i = s_i * B_`
2. Each co-signer proves correctness via a DLEQ proof (see Section 8.4)
3. The requester reconstructs `C_ = k * B_` via Lagrange interpolation over any `t` valid partial evaluations

The requesting player participates as a co-signer for their own request — they hold a secret share like every other player and contribute a partial evaluation toward the threshold.

**Why not FROST Schnorr?**

FROST produces `(R, z)` Schnorr signature pairs. The BDHKE unblinding step requires the multiplicative structure `C = C_ - r*K`, which only holds when `C_ = k * B_`. A Schnorr signature over `B_` cannot be unblinded into `k * hash_to_curve(x)`. The Threshold OPRF preserves this structure. ChillDKG is reused for key distribution, but the signing protocol is distinct.

### 8.2 Security Properties

| Property | Mechanism |
|----------|-----------|
| No single player can bias the outcome | Threshold OPRF: `t` colluders required to control `k` |
| Requester cannot bias the outcome | Requester controls `x` but not `k`; cannot evaluate `k*hash_to_curve(x)` without co-signers |
| Co-signers cannot bias the outcome | Co-signers sign the blinded `B_` without knowing `x`; cannot evaluate the result |
| Grinding is mitigated | `SHA-256(x)` committed on-chain before any partial response is returned |
| Tokens are context-bound | Each signing request commits to `(game_id, seq, action_type, prev_event_hash)` |
| Partial responses are individually verifiable | DLEQ proofs allow anyone to reject invalid partial evaluations |

### 8.3 Protocol Flow

```
1. Player generates secret x  (uniformly random, 32 bytes from CSPRNG)

2. Player publishes RANDOMNESS_REQUEST (kind 30809):
     commitment = SHA-256(x)
     B_         = hash_to_curve(x) + r*G    (r = secret blinding factor)
     context    = SHA-256("NUTCHAIN_CTX_v1" || game_id || seq || action_type || prev_event_hash)

3. Each co-signer i in signing set S (|S| = t) publishes TOPRF_PARTIAL (kind 30810):
     C_i = s_i * B_
     pi_i = DLEQ proof that C_i is consistent with S_i = s_i*G

   Note: the requesting player is also a co-signer and contributes their own
   partial evaluation toward the threshold t.

4. Requester collects t valid TOPRF_PARTIAL events:
     Verifies each pi_i against the corresponding public key share S_i
     Applies Lagrange interpolation to reconstruct:
       C_ = Sigma_{i in S} lambda_i * C_i

5. Requester publishes RANDOMNESS_REVEAL (kind 30811):
     C_ = aggregated blind evaluation
     x  = original secret
     r  = blinding factor
     C  = C_ - r*K     (unblinded result)

6. Verification (anyone):
     a. Check SHA-256(x) matches commitment in RANDOMNESS_REQUEST
     b. Recompute C_ from published TOPRF_PARTIAL events:
        - For each TOPRF_PARTIAL, verify its DLEQ proof pi_i against
          the signer's public key share S_i (derivable from DKG commitments)
        - Apply Lagrange interpolation over t valid partials
        - Check the recomputed C_ matches the C_ in RANDOMNESS_REVEAL
     c. Compute C = C_ - r*K using the revealed r and group pubkey K
     d. Check C matches the value in RANDOMNESS_REVEAL

7. Seed derivation:
     seed = SHA-256("NUTCHAIN_SEED_v1" || C.x_coordinate || context)
```

#### RANDOMNESS_REQUEST Event Schema

```json
{
  "kind": 30809,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"commitment\": \"<hex SHA-256(x)>\", \"blinded_message\": \"<hex B_>\", \"context\": \"<hex context hash>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<seq>"]]
}
```

The `d` tag uses a compound key (`game_id:seq`) to prevent relay-level replacement when a player publishes multiple randomness requests across different turns.

#### RANDOMNESS_REVEAL Event Schema

```json
{
  "kind": 30811,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"randomness_request_event_id\": \"<event id>\", \"aggregated_blind_signature\": \"<hex C_>\", \"secret\": \"<hex x>\", \"blinding_factor\": \"<hex r>\", \"unblinded_signature\": \"<hex C>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<randomness_request_event_id>"]]
}
```

- `aggregated_blind_signature` — The aggregated blind evaluation `C_` reconstructed from `t` partial evaluations via Lagrange interpolation. Verifiers recompute this from `TOPRF_PARTIAL` events and check it matches.
- `secret` — The original secret `x` whose commitment was published in `RANDOMNESS_REQUEST`.
- `blinding_factor` — The blinding factor `r` used to construct `B_`.
- `unblinded_signature` — The unblinded result `C = C_ - r*K`.

### 8.4 Threshold OPRF Signing Detail

#### DLEQ Proof

A DLEQ (Discrete Log Equality) proof demonstrates that the same secret scalar `s_i` was used in both `S_i = s_i * G` and `C_i = s_i * B_`, without revealing `s_i`. Public key shares `S_i` are computable by any verifier from the DKG commitments (see Section 12). The `public_key_share` field is included in `TOPRF_PARTIAL` events for verification convenience, but verifiers should recompute `S_i` from DKG data rather than trusting the published value.

**Construction (NutChain-specific Chaum-Pedersen Sigma protocol, non-interactive via Fiat-Shamir):**

This is a NutChain-specific construction inspired by the Chaum-Pedersen protocol [[ChaumPedersen93]](#ChaumPedersen93). It differs from Cashu NUT-12 (which omits `G` from the challenge hash and uses uncompressed point encoding) and from RFC 9497 (which uses a composite evaluation structure for batch verification). The construction below includes all public inputs in the challenge hash for domain separation and binding.

```
Public inputs:  G, B_, S_i, C_i
Prover knows:   s_i

1. Sample random nonce:  k <-$ Z_q
2. Compute commitments:  A = k*G
                         Z = k*B_
3. Compute challenge:    e = SHA-256("NUTCHAIN_DLEQ_v1" || G || B_ || S_i || C_i || A || Z)
4. Compute response:     s = k - s_i*e   (mod group order q)

Proof: pi_i = (e, s)
```

**Verification:**

```
A' = s*G + e*S_i
Z' = s*B_ + e*C_i
Check: e == SHA-256("NUTCHAIN_DLEQ_v1" || G || B_ || S_i || C_i || A' || Z')
```

All curve points in the challenge hash are SEC1 compressed (33 bytes). See Section 4.3 for encoding details.

A `TOPRF_PARTIAL` event whose proof fails this check is invalid and must be ignored.

#### Lagrange Interpolation

Player indices are 0-based (`{0, 1, ..., n-1}`), but each player `i`'s secret share is the polynomial evaluated at point `i+1` (i.e., `f(1), f(2), ..., f(n)`). This ensures no player holds `f(0) = k`, the group secret. Lagrange interpolation uses these evaluation points, not the raw indices.

Given signing set `S` with evaluation points `P_S = {i+1 : i in S}` and `|S| = t`, the Lagrange coefficient for evaluation point `p` at target `0` is:

```
lambda_p = Pi_{j in P_S, j != p} (-j) / (p - j)   (mod group order)
```

The aggregated blind evaluation (using player index `i` where evaluation point is `i+1`):

```
C_ = Sigma_{i in S} lambda_{i+1} * C_i
```

The choice of signing set `S` does not affect the result — any `t` valid partial evaluations produce the same `C_`. Requesters should use the first `t` valid `TOPRF_PARTIAL` events received.

#### TOPRF_PARTIAL Event Schema

```json
{
  "kind": 30810,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"randomness_request_event_id\": \"<event id of RANDOMNESS_REQUEST>\", \"player_index\": 2, \"partial_response\": \"<hex C_i>\", \"public_key_share\": \"<hex S_i>\", \"validated_context\": \"<hex context hash>\", \"dleq_proof\": {\"e\": \"<hex scalar>\", \"s\": \"<hex scalar>\"}}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<RANDOMNESS_REQUEST event id>"]]
}
```

- `validated_context` — The context hash that this co-signer independently computed and validated before producing the partial response. Verifiers can confirm that all co-signers agreed on the same game context.

The `d` tag uses a compound key to prevent relay-level replacement when a player produces `TOPRF_PARTIAL` events for multiple randomness requests within the same game (see Section 4.2).

### 8.5 Seed-Based Value Derivation

Each turn that requires randomness produces exactly one seed from a single `RANDOMNESS_REQUEST`. The game rule function derives all needed random values from that seed using a deterministic counter-based KDF:

```
seed    = SHA-256("NUTCHAIN_SEED_v1" || C.x_coordinate || context)
value_0 = SHA-256("NUTCHAIN_VAL_v1" || seed || 0x00000000)
value_1 = SHA-256("NUTCHAIN_VAL_v1" || seed || 0x00000001)
value_2 = SHA-256("NUTCHAIN_VAL_v1" || seed || 0x00000002)
...
value_k = SHA-256("NUTCHAIN_VAL_v1" || seed || k as big-endian uint32)
```

To map a value to a range `[0, N)`:

```
result = value_k interpreted as big-endian uint256, mod N
```

For small `N` relative to 2^256, modular bias is negligible. Game rules may specify rejection sampling for applications requiring strict uniformity.

The number of values derived per seed is determined entirely by the game rule function — it is not declared in the `RANDOMNESS_REQUEST`. Since the seed derivation is deterministic, any verifier replaying the game rules will derive the same values.

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
context = SHA-256("NUTCHAIN_CTX_v1" || game_id || seq || action_type || prev_event_hash)
```

See Section 4.3 for the exact encoding of each field in this hash.

Co-signers must verify that the `context` in a `RANDOMNESS_REQUEST` matches the expected value derived from their own local view of the game state before producing a partial response. Specifically, the co-signer independently computes the expected context from the `game_id`, the current `seq`, the `action_type`, and the hash of the previous event in their local chain. A `TOPRF_PARTIAL` produced for a request whose context does not match the co-signer's local state must not be published.

Each co-signer includes the `validated_context` in their `TOPRF_PARTIAL` event (see Section 8.4), allowing verifiers to confirm that all co-signers agreed on the same context.

Verifiers reject `RANDOMNESS_REVEAL` events whose context does not match the game state at the point of the corresponding `RANDOMNESS_REQUEST`.

### 8.8 Worked Example (n=4, t=3)

**Setup:** 4 players with indices `{0, 1, 2, 3}`, corresponding to evaluation points `{1, 2, 3, 4}`. Threshold `t = floor(8/3) + 1 = 3`. Player 3 is offline.

**Signing set:** Players `{0, 1, 2}`, evaluation points `P_S = {1, 2, 3}`

**Lagrange coefficients at 0** (mod group order `q`):

```
lambda_1 = (0-2)/(1-2) * (0-3)/(1-3)
         = (-2)/(-1) * (-3)/(-2)
         = 2 * 3/2
         = 3

lambda_2 = (0-1)/(2-1) * (0-3)/(2-3)
         = (-1)/(1) * (-3)/(-1)
         = -1 * 3
         = -3

lambda_3 = (0-1)/(3-1) * (0-2)/(3-2)
         = (-1)/(2) * (-2)/(1)
         = 1
```

*All division is modular inverse over the group order `q`. Sanity check: `lambda_1 + lambda_2 + lambda_3 = 3 + (-3) + 1 = 1` (this identity holds because Lagrange interpolation to point 0 reconstructs `f(0) = k`, and the coefficients form a partition of unity at the target point).*

**Reconstruction:**

```
C_ = 3*C_0 + (-3)*C_1 + 1*C_2
```

*(where `C_i` is the partial evaluation from player `i`, weighted by the Lagrange coefficient for that player's evaluation point)*

**Full flow:**

```
Player 0 generates x, computes B_ = hash_to_curve(x) + r*G
Player 0 publishes RANDOMNESS_REQUEST (commitment, B_, context)

Player 0 computes C_0 = s_0 * B_, generates pi_0, publishes TOPRF_PARTIAL
Player 1 computes C_1 = s_1 * B_, generates pi_1, publishes TOPRF_PARTIAL
Player 2 computes C_2 = s_2 * B_, generates pi_2, publishes TOPRF_PARTIAL
(Player 3 offline — not needed, t=3 satisfied)

Note: Player 0 is both the requester and a co-signer. Their partial
evaluation counts toward the threshold t=3.

Player 0 verifies pi_0, pi_1, pi_2 against S_0, S_1, S_2
Player 0 computes C_ = 3*C_0 - 3*C_1 + 1*C_2
Player 0 computes C = C_ - r*K
Player 0 publishes RANDOMNESS_REVEAL (C_, x, r, C)

Anyone verifies:
  a. SHA-256(x) matches RANDOMNESS_REQUEST commitment
  b. Recompute C_ from TOPRF_PARTIAL events via Lagrange
  c. Check recomputed C_ matches C_ in RANDOMNESS_REVEAL
  d. C = C_ - r*K matches RANDOMNESS_REVEAL

seed = SHA-256("NUTCHAIN_SEED_v1" || C.x_coordinate || context)
```

---

## 9. Gameplay Events

### 9.1 GAME_ACTION

A `GAME_ACTION` event represents a player's move or action within the game. The `action_data` field is entirely game-specific — its structure and semantics are defined by the game rule implementation identified by `rules_hash`. The remaining fields are protocol-level and must be present in every `GAME_ACTION`.

```json
{
  "kind": 30808,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"player_index\": 1, \"action_type\": \"<game-defined action type>\", \"action_data\": <game-specific JSON value>}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<seq>"]]
}
```

- `seq` — Sequence number in the event chain.
- `game_id` — The game instance identifier.
- `player_index` — The 0-based index of the acting player.
- `action_type` — A string identifying the type of action. Used in context binding for randomness (Section 8.7). Defined by the game rule implementation.
- `action_data` — Arbitrary JSON value whose structure is defined by the game rule implementation. May be an object, array, string, number, or null.

The game rule function validates whether the action is legal given the current game state. Invalid actions (wrong player, illegal move, malformed data) are rejected during state derivation.

### 9.2 Private Game State (Commit-Reveal)

Players may maintain hidden state using SHA-256 commit-reveal pairs published as Nostr events.

#### COMMIT

```json
{
  "kind": 30812,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"commitment\": \"<SHA-256(nonce || len(secret) || secret)>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<seq>"]]
}
```

The `nonce` must be uniformly random (minimum 16 bytes) to prevent preimage recovery via dictionary attack. The `secret` may be arbitrary game data — a hand of cards, a hidden unit position, a planned move.

The commitment is computed as `SHA-256(nonce || len(secret) || secret)`, where `nonce` is the raw random bytes, `len(secret)` is the byte length of the UTF-8 encoded secret as a big-endian uint16, and `secret` is the UTF-8 encoded secret data. The nonce is placed first and the secret is length-prefixed to prevent ambiguity when the boundary between nonce and secret is unknown to verifiers. See Section 4.3 for encoding details.

#### REVEAL

```json
{
  "kind": 30813,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"secret\": \"<plaintext>\", \"nonce\": \"<hex>\", \"commit_event_id\": \"<event id of COMMIT>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>:<seq>"]]
}
```

Verifiers check:
- `SHA-256(nonce || len(secret) || secret)` matches the `commitment` in the referenced `COMMIT` event (using the encoding from Section 4.3)
- The `COMMIT` event appears earlier in the event chain than this `REVEAL` (i.e., has a lower `seq` number) — a reveal without a prior commit is invalid

Random seeds from `RANDOMNESS_REVEAL` may be used as the basis for private draws that are themselves committed before the seed is known, allowing fully private and verifiable card dealing or similar mechanics.

---

## 10. Turn Timeout & Forfeit

Each game configures `turn_timeout_seconds` in `GAME_CREATE`. The timeout is measured from the `created_at` timestamp of the event that created the obligation for a specific player (the "triggering event"). Since the event chain is linear and all events are hash-linked, the triggering event and its timestamp are unambiguous.

Note that `created_at` is self-reported by the event author per NIP-01. Timeout enforcement relies on honest-majority agreement among peers about whether sufficient time has elapsed. In practice, peers should allow reasonable clock skew tolerance (e.g., a few seconds) and any peer asserting a forfeit must reference the specific triggering event whose `created_at` serves as the start of the timeout window.

Timeout applies at every stage:

| Stage | Responsible Player | Consequence |
|-------|--------------------|-------------|
| Publishing `GAME_ACTION` | The player whose turn it is | Forfeit |
| Publishing `RANDOMNESS_REQUEST` | The player who needs randomness | Forfeit |
| Publishing `TOPRF_PARTIAL` | Each co-signer | That player forfeits (game may continue if remaining players still meet threshold) |
| Publishing `RANDOMNESS_REVEAL` | The requesting player | Forfeit |

When a forfeit condition is met, any peer may publish `GAME_END` citing the timed-out event ID and the offending player's pubkey. The game rule implementation determines what "forfeit" means for the specific game (loss, disqualification, substitution).

### GAME_END Event Schema

```json
{
  "kind": 30814,
  "content": "{\"seq\": <n>, \"game_id\": \"<game_id>\", \"reason\": \"<forfeit|completed|aborted>\", \"result\": <game-specific result JSON>, \"forfeiting_player\": <player_index or null>, \"timed_out_event_id\": \"<event id or null>\"}",
  "tags": [["e", "<previous event id>"], ["d", "<game_id>"]]
}
```

- `reason` — One of `"forfeit"` (a player timed out), `"completed"` (game ended normally), or `"aborted"` (game terminated by mutual agreement or error).
- `result` — Game-specific JSON value encoding the outcome (e.g., winner, scores). Defined by the game rule implementation.
- `forfeiting_player` — The 0-based index of the player who forfeited, or `null` if the game ended normally.
- `timed_out_event_id` — The event ID that was not responded to in time, or `null` if not a forfeit.

---

## 11. Threat Model

| Threat | Mitigation |
|--------|------------|
| Single player biases randomness | Threshold OPRF: biasing `C_` requires controlling `t` secret shares |
| Requesting player grinds for favorable `x` | Public `SHA-256(x)` commitment precedes any partial response; abandonment triggers forfeit |
| Co-signer produces invalid partial response | DLEQ proof is published alongside `C_i`; invalid proofs are verifiably rejected |
| Token reused across game contexts | Context field `SHA-256("NUTCHAIN_CTX_v1" \|\| game_id \|\| seq \|\| action_type \|\| prev_event_hash)` uniquely binds each token |
| Player abandons after learning seed | Timeout + forfeit; outcome of revealed seed is recorded in `RANDOMNESS_REVEAL` on-chain |
| Coalition of `t-1` players colludes | Insufficient shares to reconstruct `k`; OPRF output is computationally indistinguishable from random |
| Coalition of `t` or more players colludes | Threshold does not prevent this; `t = floor(2n/3) + 1` makes this a strict Byzantine majority |
| Event ordering dispute | Strict linear chain with hash links and sequence numbers; no forks possible under correct operation |
| Forged game state | All events are Nostr-signed; state is derived deterministically from the auditable public event chain |
| DKG participant publishes invalid shares | Share verification against Feldman commitments detects cheating; CertEq ensures all players agree on the DKG outcome. `DKG_BLAME` events provide on-chain accountability |
| DKG participant withholds CertEq signature | DKG cannot finalize without all `n` signatures; game does not start; no funds at risk |
| Game creator denies service | Game creator can withhold ACKs or DKG aggregation, preventing game start. Mitigation: no funds or game state are at risk before `GAME_START`; players can detect non-progress via timeout and abandon. The creator role carries no cryptographic privilege |
| Co-signers disagree on game context | Each `TOPRF_PARTIAL` includes a `validated_context` field; verifiers can detect context disagreement |

---

## 12. Cryptographic Construction Reference

### Primitives

| Primitive | Specification |
|-----------|---------------|
| Elliptic curve | Secp256k1 (consistent with Nostr and Bitcoin) |
| Hash to curve | `hash_to_curve` per [[CashuNUT00]](#CashuNUT00) (try-and-increment, domain separator `b"Secp256k1_HashToCurve_Cashu_"`, counter as little-endian uint32) |
| Distributed key generation | [[ChillDKG]](#ChillDKG) (EncPedPop + CertEq) |
| BDHKE | [[CashuNUT00]](#CashuNUT00) |
| DLEQ proofs | NutChain-specific Chaum-Pedersen Sigma protocol [[ChaumPedersen93]](#ChaumPedersen93), non-interactive via Fiat-Shamir with domain separator `"NUTCHAIN_DLEQ_v1"`. See Section 8.4 for the full construction |
| Threshold OPRF | [[JKKX17]](#JKKX17) |
| General hashing | SHA-256 |

### Domain Separation

All hash operations in NutChain are domain-separated to prevent cross-protocol attacks:

| Context | Domain Separator |
|---------|-----------------|
| DLEQ challenge | `"NUTCHAIN_DLEQ_v1"` |
| Randomness context | `"NUTCHAIN_CTX_v1"` |
| Seed derivation | `"NUTCHAIN_SEED_v1"` |
| Value derivation | `"NUTCHAIN_VAL_v1"` |
| DKG ECDH pad (cross-participant) | `"BIP DKG/encpedpop ecdh"` (ChillDKG) |
| DKG ECDH pad (self-encryption) | `"BIP DKG/encaps_multi self_pad"` (ChillDKG) |

### Public Key Share Derivation

Public key shares `S_j` for player `j` (0-indexed) are computable by any verifier from the DKG commitments, without any private information. The evaluation point is `j+1` (never 0, since `f(0) = k` is the group secret):

```
S_j = Sigma_{k=0}^{t-1} sum_coms[k] * (j+1)^k
```

This means DLEQ proofs in `TOPRF_PARTIAL` events are fully verifiable by any observer, not just the game participants.

---

## 13. References

### Academic Literature

**[ChaumPedersen93]** <a name="ChaumPedersen93"></a>
David Chaum and Torben Pryds Pedersen.
"Wallet Databases with Observers."
*CRYPTO 1992*, LNCS 740, pp. 89-105. Springer, 1993.
https://link.springer.com/chapter/10.1007/3-540-48071-4_7

Introduces the DLEQ sigma protocol that inspired the construction in Section 8.4. NutChain uses a custom variant with a domain-separated challenge hash including all public inputs (see Section 8.4 for details). Zero-knowledge follows from standard sigma-protocol analysis. Made non-interactive via the Fiat-Shamir transform. [[JKKX17]](#JKKX17) proves UC security of the Threshold OPRF construction that builds on this proof.

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

**[CGRS23]** <a name="CGRS23"></a>
Chu, Gerhart, Ruffing, and Schroeder.
"Practical Schnorr Threshold Signatures Without the Algebraic Group Model."
Cryptology ePrint Archive, Paper 2023/899.
https://ia.cr/2023/899

Security proof for PedPop (the DKG underlying ChillDKG) composed with FROST. Establishes that SimplPedPop is secure when combined with FROST signing. See Section 6.3 for discussion of the known limitation regarding composability with Threshold OPRF.

---

### Standards and Specifications

**[RFC9497]** <a name="RFC9497"></a>
A. Davidson, A. Faz-Hernandez, N. Sullivan, C. A. Wood.
"Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups."
IRTF CFRG, December 2023.
https://www.rfc-editor.org/rfc/rfc9497

Reference for the single-signer VOPRF construction. NutChain's DLEQ proof (Section 8.4) is a custom Chaum-Pedersen construction, not the RFC 9497 proof structure. The threshold extension is not covered by this RFC; see [[JKKX17]](#JKKX17).

---

**[CashuNUT00]** <a name="CashuNUT00"></a>
Cashu contributors.
"NUT-00: Notation, Utilization, and Terminology."
https://github.com/cashubtc/nuts/blob/main/00.md

Specifies the BDHKE scheme and `hash_to_curve` function that form the single-signer base of the DASoR protocol (Section 8.1).

---

**[CashuNUT12]** <a name="CashuNUT12"></a>
Cashu contributors.
"NUT-12: Offline ecash signature validation."
https://github.com/cashubtc/nuts/blob/main/12.md

Specifies DLEQ proofs for single-signer Cashu blind signatures. NutChain's threshold DLEQ construction (Section 8.4) is distinct from NUT-12's single-signer proof, which omits the generator `G` from the challenge hash and uses uncompressed point encoding.

---

**[ChillDKG]** <a name="ChillDKG"></a>
Tim Ruffing, Jonas Nick, and Sivaram Dhakshinamoorthy.
"ChillDKG: Distributed Key Generation for FROST."
BIP draft (Blockstream Research).
https://github.com/BlockstreamResearch/bip-frost-dkg

Standalone DKG protocol requiring no trusted dealer, no external secure channels, and no external consensus mechanism. Incorporates EncPedPop (ECDH-encrypted share delivery) and CertEq (signature-certificate-based agreement). Referenced in Section 6.3. Note: ChillDKG is designed for FROST and explicitly warns against use with other threshold schemes. See Section 6.3 Security Note for NutChain's known deviation.

---

### Prior Art and Implementations

**[Fedimint]** <a name="Fedimint"></a>
Fedimint contributors.
"Fedimint: A Federated Chaumian Mint."
https://github.com/fedimint/fedimint

Production implementation of threshold blind signatures using Feldman secret sharing, DLEQ proofs, and Lagrange interpolation over secp256k1. The closest existing reference implementation to the DASoR protocol in Section 8.

---

### Note on Standardization Status

The threshold extension of OPRF — distributing the signing key across multiple parties via Feldman secret sharing and reconstructing via Lagrange interpolation — is described in [[JKKX17]](#JKKX17) and implemented in [[Fedimint]](#Fedimint), but does not yet have a finalized IETF RFC. [[RFC9497]](#RFC9497) covers only the single-signer case. Implementers of the DASoR protocol should treat [[JKKX17]](#JKKX17) as the primary cryptographic reference and [[Fedimint]](#Fedimint) as the primary implementation reference for the threshold variant.

ChillDKG [[ChillDKG]](#ChillDKG) is a BIP draft and not yet finalized. Its security proof [[CGRS23]](#CGRS23) covers composition with FROST Schnorr signing; composition with Threshold OPRF is a known limitation (see Section 6.3).
