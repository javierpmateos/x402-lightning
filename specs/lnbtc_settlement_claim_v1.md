# Lightning settlement claim (`lnbtc.settlement.v1`) and attester endorsement

**Status:** v1 test profile. The registry shape and the endorsement states were accepted for this profile on [x402-foundation/x402#1195](https://github.com/x402-foundation/x402/issues/1195#issuecomment-6155547130); the endorsement proposal and the `OTHER_NODE` state are in [this comment](https://github.com/x402-foundation/x402/issues/1195#issuecomment-6018962237) and [this one](https://github.com/x402-foundation/x402/issues/1195#issuecomment-6068619963).
**Vectors:** [`test/vectors/lnbtc-settlement-v1.json`](../test/vectors/lnbtc-settlement-v1.json), [`test/vectors/lnbtc-endorsement-v1.json`](../test/vectors/lnbtc-endorsement-v1.json).
**Reference implementation:** [`src/settlement-claim/index.ts`](../src/settlement-claim/index.ts) for claims and the key registry. The endorsement (§6) has no reference implementation here yet; its vectors define the expected results.

This document collects what was agreed in that thread into one place, plus the verification rules a consumer needs to use a claim. Where it and the thread disagree on what was agreed, the thread is the record and this document has a bug.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in RFC 2119.

## 1. What a claim is

A settlement claim is an **attestation**: an attester's signed statement that a Lightning payment for an x402 request was settled and that the attester consumed it. It is not a proof of payment that can be checked without trusting the attester. The claim does not carry the preimage, so `SHA256(preimage) = payment_hash` is the attester's assertion, not something the consumer verifies.

What the consumer can check without trusting the attester:

- that the attester's key signed exactly this claim;
- that the claim is consistent with the BOLT11 invoice, which the payee signed: network, payment hash, request binding, creation time, and the invoice's nominal amount and payee;
- with the expected conditions in §5.2, that the invoice is the one for the operation the consumer is authorizing.

What rests on the attester's signature alone:

- that the payment settled (Lightning leaves no public settlement record);
- `redemption`: that the attester consumed the payment (§7);
- `observed_at`: when the attester observed settlement. The only independent bound is the invoice's creation time.

The claim does not establish who controls the attester key, and does not bind a delivery receipt (SAR) to the payment. A composition between the two would need its own construction (`VERIFY(settlement) + VERIFY(SAR) != VERIFY(settlement ↔ SAR)`).

A consumer that needs settlement without trusting an attester uses the preimage-based proof of `scheme_exact_lnbtc.md` instead.

## 2. Claim members

A claim is a JSON object with three groups of members.

**Core.** Exactly the following nine members, each a non-empty string, and no others. Only the core is canonicalized and signed.

| Member | Value |
|---|---|
| `claim_version` | `"lnbtc.settlement.v1"` |
| `network` | An `lnbtc:` network identifier from `scheme_exact_lnbtc.md`: `lnbtc:000000000019d6689c085ae165831e93` (mainnet, BOLT11 currency `bc`) or `lnbtc:000000000933ea01ad0ee984209779ba` (testnet, `tb`) |
| `payment_hash` | 64 lowercase hex characters |
| `payment_request` | The BOLT11 invoice that was paid |
| `request_hash` | 64 lowercase hex characters, equal to the invoice's description hash, which commits to the request under `request_binding_profile` |
| `request_binding_profile` | `"http:1"` or `"mcp:1"` |
| `observed_at` | UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`: literal `Z`, whole seconds, a valid calendar time |
| `redemption` | `"verified-and-consumed"` (the only value defined for v1) |
| `attester_kid` | The `kid` of the attester's key in its key registry |

**Envelope.** `claim_id`, `sig_alg` and `sig`. They are not part of the core, but they are REQUIRED and verified (§5).

**Extensions.** Any other member. Extensions are not signed, do not change `claim_id`, and MUST be ignored for verification.

A verifier MUST NOT add envelope or extension members to the signed set, and MUST NOT omit or rename any core member. Member order is not a separate rule: JCS (RFC 8785) sorts members, so the canonical form of the core is fully determined by its membership.

Unknown values of `claim_version`, `network`, `request_binding_profile` and `redemption` MUST be rejected (fail closed).

**Parsing.** A claim and a registry document MUST be rejected if they contain duplicate member names or invalid Unicode (for example, lone surrogates), since different parsers would otherwise read the same bytes differently before canonicalization. The reference implementation takes already-parsed objects, so this check belongs to the code that parses the JSON text.

## 3. Derivation and signature

```
digest    = SHA-256( JCS(core) )            ; RFC 8785
claim_id  = "sha256:" || hex(digest)        ; lowercase hex
signature = Ed25519( digest )               ; over the 32 digest bytes, not over the JSON
sig       = "base64url:" || base64url(signature)   ; unpadded
sig_alg   = "Ed25519"
```

## 4. Key registry

The attester publishes its keys in the `sar-keys.json` shape:

```json
{ "keys": [ { "kid": "lnbtc-settlement-ed25519-01", "kty": "OKP", "crv": "Ed25519", "x": "<base64url public key>" } ] }
```

- Each `kid` MUST appear at most once. A registry with a repeated `kid` MUST be rejected.
- `kty` MUST be `"OKP"` and `crv` MUST be `"Ed25519"`; any other value MUST be rejected. `x` MUST decode to 32 bytes.
- `sig_alg` MUST agree with the algorithm of the key resolved through `attester_kid`; the algorithm is bound through the key, not taken from the claim.

The reference implementation applies these rules in `parseAttesterRegistry`.

How the registry is fetched and kept intact (TLS, pinning, a signed snapshot) is outside this profile. A consumer that cannot trust its copy of the registry cannot trust the attester key either, which matters more than anything in §6.

## 5. Verification

### 5.1 Claim verification

A verifier MUST perform these checks and MUST reject the claim at the first one that fails. The version comes first because it defines how everything else is read.

1. **Shape.** All nine core members are present non-empty strings; `claim_id`, `sig_alg` and `sig` are strings.
2. **Version.** `claim_version` is `lnbtc.settlement.v1`.
3. **Formats.** Every core member matches §2.
4. **claim_id.** `claim_id` equals the value derived from the core (§3). It is derived, never trusted.
5. **Key.** `attester_kid` resolves in the registry (§4).
6. **sig_alg.** Agrees with the resolved key.
7. **Signature.** `sig` is `base64url:`-prefixed, decodes to 64 bytes, and verifies over the digest with the resolved key.
8. **Invoice.** `payment_request` decodes and its signature is valid. The payee node key is the key that signature authenticates: the `n` field when present (the key recovered from the signature MUST equal it), otherwise the recovered key.
9. **Network.** The invoice currency matches `network`.
10. **payment_hash.** Equals the invoice's payment hash.
11. **request_hash.** The invoice carries a description hash, and it equals `request_hash`.
12. **observed_at.** Not earlier than the invoice's creation time.

A claim that passes §5.1 is authentic and consistent with a well-formed, payee-signed invoice. That does not yet say the invoice is the one for the operation the consumer is about to authorize.

### 5.2 Expected conditions

A consumer that uses a claim to authorize an x402 operation MUST supply the conditions it expects and MUST reject the claim if any differs:

13. **Payee.** The payee node key (step 8) equals the expected payee (e.g. `PaymentRequirements.payTo`).
14. **Request.** `request_hash` equals the request binding digest the consumer computed itself from the request it is authorizing, under `request_binding_profile`. Matching the invoice (step 11) is not enough: the consumer must compare against its own request.
15. **Amount.** The invoice's nominal amount, in millisatoshis, equals the expected amount (`PaymentRequirements.amount` in msat). An invoice without an amount never matches. As in `scheme_exact_lnbtc.md`, the nominal amount is the x402 amount; the claim does not show what the payee actually received.
16. **Network.** `network` equals the network of the requirements being satisfied.

A verifier SHOULD report which of these it checked, so a result without them is never read as one with them. The reference implementation reports `payeeChecked`, `requestChecked` and `amountChecked`.

## 6. Attester endorsement

### 6.1 Where it lives

An optional `payee_endorsement` member of the attester's registry entry. It does not change the claim or `claim_id`.

```json
{
  "kid": "lnbtc-settlement-ed25519-01", "kty": "OKP", "crv": "Ed25519", "x": "<base64url>",
  "payee_endorsement": { "format": "ln-signmessage", "node_id": "<33-byte compressed secp256k1 key, 66 lowercase hex>", "zbase": "<zbase32 signature>" }
}
```

`node_id` MUST be 66 lowercase hex characters encoding a valid compressed secp256k1 public key. `format` MUST be `"ln-signmessage"`; any other value makes the endorsement `ENDORSEMENT_INVALID`.

### 6.2 Signed message

The verifier rebuilds the message from the registry entry; it MUST NOT take a message supplied alongside the signature.

```
msg = UTF8( JCS({
  "domain":   "x402:lnbtc:attester-endorsement:v1",
  "node_id":  payee_endorsement.node_id,
  "attester": { "kid": entry.kid, "kty": entry.kty, "crv": entry.crv, "x": entry.x }
}) )
```

`attester` is exactly those four members of the registry entry, with their values, and nothing else. The message commits to the attester's key material (`x`), not only to its `kid`, so the registry cannot swap the key under an endorsed `kid`.

### 6.3 Signature format (`ln-signmessage`)

The message-signing format shared by lnd and Core Lightning:

```
zbase = zbase32( SigRec )
SigRec = (31 + recovery_id) || compact_signature(64 bytes)
signed digest = SHA-256( SHA-256( "Lightning Signed Message:" || msg ) )
```

Verification recovers the public key and compares it with `node_id`. Single-hash signatures (lnd `SignMessage` with `single_hash`) are invalid.

### 6.4 States

Per claim, the endorsement axis has four states, kept distinct:

| State | When | Reported with |
|---|---|---|
| `ENDORSEMENT_VERIFIED` | The signature recovers `node_id`, and `node_id` is the payee node key of the claim's invoice (§5.1 step 8) | — |
| `ENDORSEMENT_OTHER_NODE` | The signature recovers `node_id`, but `node_id` is not that payee | `node_id`, required with this state and absent with the others |
| `ENDORSEMENT_NOT_PRESENT` | The registry entry, as received, has no `payee_endorsement` | — |
| `ENDORSEMENT_INVALID` | `payee_endorsement` is present but does not verify: unknown `format`, malformed `node_id`, bad zbase32, wrong length, recovery fails, or the recovered key is not `node_id` | — |

`ENDORSEMENT_INVALID` is a fact about the registry entry: it was tampered with or misconfigured. A verifier MUST NOT report it, and a consumer MUST NOT treat it, as `ENDORSEMENT_NOT_PRESENT`.

`ENDORSEMENT_NOT_PRESENT` describes the entry the verifier received. If the registry copy was altered to remove an endorsement, the verifier cannot tell; detecting that is a matter of registry integrity (§4), not of the endorsement signature.

### 6.5 Control axis

A valid endorsement shows that the node endorsed the attester key. It does not show common control, separate control, or economic or operational independence. The attester key (Ed25519) and the node key (secp256k1) share nothing that could establish either, so a v1 verifier always reports `CONTROL_RELATIONSHIP_UNKNOWN` on the control axis. `SAME_CONTROL_ESTABLISHED` and `SEPARATE_CONTROL_ESTABLISHED` are reserved until an evidence type is defined for them.

### 6.6 Limitation: no expiry or revocation

An endorsement has no validity period and no revocation mechanism in v1. It stays valid for as long as it stays in the registry. A node that wants to withdraw an endorsement can only have it removed from the registry, which consumers holding an older copy will not see.

## 7. Redemption and the spent set

`redemption: "verified-and-consumed"` is a commitment by the attester, not a property of Lightning: a preimage is not intrinsically single-use. An attester that issues claims MUST:

- key its spent set by the pair `(network, payment_hash)`;
- insert into it atomically before signing a claim, so that two concurrent workers cannot both issue a claim for the same payment;
- persist it across restarts;
- refuse to issue a second claim for a pair already in the set.

This matches the replay rule of `scheme_exact_lnbtc.md`. The spent set is not externally verifiable; this section defines what the attester commits to, not something a consumer can check.

## 8. Shared rule

A verifier never reports a broken or tampered input as an absent one. Collapsing the two forces every honest consumer to treat any absence as a possible tamper, which applies the worst case to the common case. This holds for the endorsement states above and for any other place a verifier distinguishes "missing" from "present but invalid". It covers inputs the verifier receives; an input removed before it reaches the verifier is a matter of the channel's integrity (§6.4).

## 9. Test vectors

- [`lnbtc-settlement-v1.json`](../test/vectors/lnbtc-settlement-v1.json): signing key (RFC 8032 §7.1 TEST 1), registry, `core_fields`, the core, its canonical form and digest, and the signed claim. Negatives: `claim_version` changed to v2 and v0 (reject), the core without `claim_version` and the core with an extension member inside it (different digest, signature does not verify), and an extension member outside the core (verifies, same `claim_id`). The claim's invoice is for 25 000 msat; its payee is the node with private key 0x00…01.
- [`lnbtc-endorsement-v1.json`](../test/vectors/lnbtc-endorsement-v1.json): `VERIFIED` (node key 0x00…01, the invoice payee) and `OTHER_NODE` (node key 0x00…02), with private keys, messages and digests; `NOT_PRESENT`; and an `INVALID` case (the `VERIFIED` signature with `node_id` swapped). Signatures are RFC 6979 deterministic and reproduce exactly.

## Acknowledgements

The endorsement axis, the four states and the registry shape come from review by @nutstrut on #1195. The explicit negatives and the normative statement of the signed set follow an independent verification of the vectors by @goun7.
