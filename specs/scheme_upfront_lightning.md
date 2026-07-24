# Upfront Payment Scheme for Bitcoin Lightning Network (`upfront`)

**Status:** Draft
**Author:** Javier Mateos (@javierpmateos)

## Scheme Name

`upfront`

## Summary

This document specifies the `upfront` payment scheme for the Bitcoin Lightning
Network, under the **payment-proof (client-settled)** asset transfer family:
the resource server issues (directly, or requested and relayed via its facilitator) a BOLT11 invoice for the exact
amount inside the 402 response; the client pays the invoice over Lightning —
settlement completes at payment time — and retries the request presenting the
32-byte payment preimage as its payment proof. The preimage is precisely the
"cryptographic settlement secret" the abstract `upfront` specification
anticipates: possession of a preimage hashing to the invoice payment hash is
proof the invoice was settled.

Lightning is arguably the canonical instance of this family: the network has
no pull-settlement primitive, payment is client-initiated by construction, and
the proof is final and self-verifying the moment it exists.

## Asset Transfer Method

`extra.assetTransferMethod: "bolt11"`. A future `"bolt12"` method (offers) can
be defined without changes to this document's verification model; see
Interoperability Notes.

## How the Core Properties Are Satisfied

The abstract `upfront` specification requires four properties of every
implementation. This method satisfies them as follows:

1. **Settle-before-execute ordering.** Structural: the preimage cannot exist
   until the payment has settled (it is revealed by the recipient's node upon
   accepting the HTLC). A request carrying a valid proof is, by definition, a
   request whose payment is already final. If verification fails, the server
   MUST NOT execute the resource.
2. **Exact amount.** The invoice encodes the server-specified amount;
   verification compares amounts in millisatoshi after decoding (Rule 5).
3. **Recipient binding.** The invoice is signed by the recipient node key,
   which MUST equal `payTo` (Rule 4). Neither facilitator nor any relayer can
   redirect funds — the client pays the recipient-signed invoice directly, and
   the facilitator never holds or moves funds.
4. **Single-use / replay protection.** The preimage is a bearer proof;
   verifiers MUST track consumed payment hashes and reject reuse (Rule 8).

Refunds are out of protocol per the abstract specification; clients opt in to
`upfront` semantics acknowledging delivery risk, and SHOULD prefer `exact`
where a server offers both for the same resource.

## Network Identifier (CAIP-2)

Lightning is a payment network over Bitcoin, not a chain. This implementation
uses the underlying chain's `bip122` CAIP-2 identifier; the rail is fully
determined by `scheme: "upfront"` + `extra.assetTransferMethod: "bolt11"`:

| Network         | CAIP-2 identifier                          |
| --------------- | ------------------------------------------ |
| Bitcoin mainnet | `bip122:000000000019d6689c085ae165831e93`  |
| Signet          | `bip122:00000008819873e925422c1ff0f99f7c`  |
| Testnet3        | `bip122:000000000933ea01ad0ee984209779ba`  |

## Finality Class

Within the payment-proof family, proof types differ in finality semantics:
an on-chain transaction hash is **probabilistically** final (a function of
confirmation depth, requiring a per-network confirmation policy), whereas a
Lightning preimage is **deterministically** final — the proof is the
settlement, and its validity is a pure function of the request
(`SHA-256(preimage) == payment_hash` plus invoice validation), with no node
query, RPC call, or confirmation policy involved. Verifiers implementing this
method need no chain access at all.

## Protocol Flow

1. Client requests a protected resource.
2. Server responds `402` with `PAYMENT-REQUIRED` advertising an `accepts`
   entry per this document, including a BOLT11 invoice for the exact amount.
3. Client validates the invoice against the requirements (amount, payment
   hash, binding — Rules 3–7, which clients SHOULD run before paying), then
   pays the invoice over Lightning and obtains the preimage.
4. Client retries with `PAYMENT-SIGNATURE` carrying the preimage.
5. Server verifies locally or via a facilitator (`/verify`, `/settle`) and,
   only on success, executes the route handler and responds `200` with
   `PAYMENT-RESPONSE`.

## x402 v2 Headers

- `PAYMENT-REQUIRED` — server payment requirements (base64 JSON).
- `PAYMENT-SIGNATURE` — client payment payload (base64 JSON).
- `PAYMENT-RESPONSE` — settlement result (base64 JSON).

## `PaymentRequirements` for `upfront`

```json
{
  "scheme": "upfront",
  "network": "bip122:000000000019d6689c085ae165831e93",
  "amount": "1500",
  "asset": "BTC",
  "payTo": "03a2...node_pubkey...9f",
  "maxTimeoutSeconds": 60,
  "extra": {
    "assetTransferMethod": "bolt11",
    "denomination": "msat",
    "invoice": "lnbc15n1p...bolt11...",
    "paymentHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "invoiceExpiry": 1784102400,
    "requirementsHash": "b1946ac92492d2347c6235b4d2611184c9f6f6f2d2c2a3f6b9d0e1c2a3b4c5d6",
    "fiatQuote": {
      "amount": "0.001",
      "currency": "USD",
      "rate": "65743.69",
      "rateTimestamp": 1784098800
    }
  }
}
```

### Field Definitions

| Field                        | Required | Description                                                             |
| ---------------------------- | -------- | ----------------------------------------------------------------------- |
| `amount`                     | Required | Invoice amount in `extra.denomination` units (`msat` RECOMMENDED)       |
| `asset`                      | Required | `"BTC"`                                                                 |
| `payTo`                      | Required | Recipient Lightning node public key (33-byte compressed secp256k1, hex) |
| `extra.assetTransferMethod`  | Required | `"bolt11"`                                                              |
| `extra.denomination`         | Required | `"msat"` or `"sat"`                                                     |
| `extra.invoice`              | Required | BOLT11 invoice                                                          |
| `extra.paymentHash`          | Required | Invoice payment hash (convenience copy; MUST match decoded invoice)     |
| `extra.invoiceExpiry`        | Required | Unix time after which the invoice is invalid; MUST equal invoice creation timestamp plus expiry (Rule 6) |
| `extra.requirementsHash`     | Required | Commitment binding invoice to resource + requirements (see below)       |
| `extra.fiatQuote`            | Optional | Informational fiat context; not verified unless upgraded by extension   |

### Requirements Binding (`description_hash`)

The binding is MANDATORY in this profile. The issuer MUST set the BOLT11 `h`
field (`description_hash`) to:

```
description_hash = SHA-256( JCS({
  resource:     <ResourceInfo from the PaymentRequired envelope>,
  requirements: <this PaymentRequirements entry, minus extra.invoice and extra.requirementsHash>
}) )
```

where `JCS` is RFC 8785 JSON Canonicalization; the same value is published as
`extra.requirementsHash`. Because BOLT11 invoices are signed by the recipient
node key, the invoice becomes a recipient-signed commitment to the full
payment terms — closing requirements-substitution attacks without any
signature beyond what BOLT11 already carries.

The commitment deliberately covers the `ResourceInfo` object as well as the
requirements. In x402 v2 `resource` lives in the `PaymentRequired` envelope
and is echoed by the client in `PaymentPayload`; a facilitator receives it
only through the client path and has no independently authenticated view of
it. Binding it here makes that client-supplied value verifiable against the
recipient's signature, which is what allows a facilitator to attest to the
resource at all. Verifiers recompute the hash using
`paymentPayload.resource`; a substituted resource fails Rule 7.

Extensions carrying richer invoice metadata participate by committing their
canonical payload inside the requirements object before hashing.

## `PaymentPayload` for `upfront`

```json
{
  "x402Version": 2,
  "resource": {
    "url": "https://api.example.com/v1/quote",
    "description": "Per-request access to /v1/quote",
    "mimeType": "application/json"
  },
  "accepted": { "...": "the chosen PaymentRequirements object, echoed" },
  "payload": {
    "paymentHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "preimage": "6c9d0e1c2a3b4c5d6b1946ac92492d2347c6235b4d2611184c9f6f6f2d2c2a3f"
  }
}
```

### Payload Fields

| Field         | Required | Description                                                  |
| ------------- | -------- | ------------------------------------------------------------ |
| `preimage`    | Required | 32-byte hex payment preimage obtained upon settlement        |
| `paymentHash` | Required | MUST equal `SHA-256(preimage)` and match the invoice         |

`resource` is OPTIONAL in the base v2 `PaymentPayload` but REQUIRED in this
profile: it is covered by the requirements binding and verified in Rule 7.

The preimage is a self-verifying payment proof: any party can verify it, in
contrast with invoice-in-payload patterns whose verification requires
querying the recipient's own wallet.

## Facilitator Verification Rules (MUST)

A facilitator (or a resource server verifying locally) MUST enforce:

### 1. Envelope Checks (x402 v2)

Reject if `paymentPayload.x402Version != 2`; if
`paymentPayload.accepted.scheme != "upfront"`; if `accepted.network` is
unsupported; or if `accepted` does not match `paymentRequirements` on
`scheme`, `network`, `asset`, `payTo`, `amount`, `maxTimeoutSeconds`, or the
required `extra` keys (`assetTransferMethod`, `denomination`, `invoice`,
`paymentHash`, `invoiceExpiry`, `requirementsHash`).

This comparison exists so that a client cannot select an offer different from
the one it was served; it is not the security boundary for the values it
covers. Rules 6 and 7 validate `invoiceExpiry` and `requirementsHash` against
the authoritative `paymentRequirements` supplied by the resource server, never
against the client echo.

### 2. Preimage Validity

`SHA-256(payload.preimage)` MUST equal `payload.paymentHash` (case-insensitive
hex, 32 bytes each).

### 3. Invoice Consistency

Decode `extra.invoice`. Its payment hash MUST equal `payload.paymentHash` and
`extra.paymentHash`. If decoding fails, verification MUST fail.

### 4. Signer Validation

The invoice signature MUST be valid and recover to `payTo`.

### 5. Amount Validation

The invoice amount, compared in millisatoshis after decoding, MUST equal
`amount` interpreted per `extra.denomination`. Never trust JSON amounts alone.

### 6. Expiry

`extra.invoiceExpiry` MUST equal the decoded invoice creation timestamp
plus its expiry. The invoice MUST NOT be expired at verification time, and
the proof MUST be presented within `maxTimeoutSeconds` of invoice creation.

### 7. Requirements Binding (mandatory)

The decoded invoice MUST carry a `description_hash`; an invoice without one
MUST be rejected in this profile. `paymentPayload.resource` MUST be present.
The `description_hash` MUST recompute from the canonical
`{resource, requirements}` object per the binding rule above, and
`extra.requirementsHash` MUST equal it. Anchoring the check to the signed
artifact means that neither stripping the mutable `extra.requirementsHash`
field nor substituting the client-echoed `resource` can go undetected.

### 8. Single Use

The payment hash MUST NOT have been accepted before. Verifiers maintain a
spent-set keyed by payment hash, retained at least until invoice expiry plus a
safety margin. Resource servers using multiple facilitators for the same
routes MUST share or route-partition the spent-set; otherwise a proof could be
redeemed once per facilitator.

Rules 1–7 are pure functions of the request and require no network access.
Facilitators MAY additionally cross-check invoice state against the issuing
node as defense in depth.

## Settlement

Per the payment-proof family, the client has already settled; there is no
facilitator settlement step. `/settle` performs the verification rules above
(including Rule 8) and returns the settlement response; `/verify` runs Rules
1–7 only, keeping it idempotent, with redemption at `/settle`. The
settle-before-execute ordering is enforced by the server invoking the route
handler only after a successful `/settle`.

## `SettlementResponse`

```json
{
  "success": true,
  "transaction": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "network": "bip122:000000000019d6689c085ae165831e93",
  "payer": null
}
```

| Field         | Type           | Description                                                    |
| ------------- | -------------- | -------------------------------------------------------------- |
| `success`     | boolean        | Settlement success status                                      |
| `transaction` | string         | Payment hash (Lightning payments have no on-chain txid)        |
| `network`     | string         | CAIP-2 network identifier (same value as in requirements)      |
| `payer`       | string \| null | `null`; Lightning does not natively identify payers            |

Facilitator-registered extensions MAY populate `extensions` via the standard
extension pipeline. Where a portable receipt is needed, the RECOMMENDED shape
is composition rather than widening an existing receipt format: a separately
signed Lightning settlement claim carrying payment hash, amount, payee,
requirements commitment, facilitator observation time and redemption result,
which other receipt formats reference by digest. A payment hash placed in an
unsigned extension envelope is correlation context, not an attested
settlement identifier, since it can be replaced without invalidating the
outer signature.

The preimage MUST NOT appear in any portable receipt or settlement response:
it is a bearer proof, and publishing it creates replay and disclosure risk.
Verifiers check it during settlement and attest the result; the settlement
response carries the payment hash only.

## Security Considerations

### Scope of the Settlement Proof

A valid preimage proves knowledge of the secret for a payee-signed invoice,
and therefore that the invoice was settled. It does **not** independently
prove payer identity, settlement time, or delivery of the resource. Amount,
payee, network and resource are established by the recipient-signed
requirements binding (Rule 7) — not implied by the preimage. Any receipt or
attestation built on this profile MUST reflect that separation, and any
timestamp a facilitator emits is its own observation time: Lightning does not
expose a native settlement timestamp to the verifier.

### Trust Minimization

The facilitator never holds keys or funds and cannot forge settlements
without a preimage. A compromised facilitator can only falsely reject valid
proofs (denial of service); resource servers MAY fall back to local
verification.

### Replay and Race Protection

The preimage is a bearer proof. Single use per payment hash (Rule 8) is
mandatory; transport-layer protections of the base specification apply. The
spent-set MUST be shared across facilitator instances serving the same routes.

### Requirements Substitution

Without the `description_hash` binding, an intermediary could pair a cheap
invoice with expensive requirements. Issuers MUST bind (Rule 7); clients
SHOULD verify the binding before paying. Verifiers anchor the check to the
invoice signed `description_hash` (Rule 7), so removing the unsigned
`extra.requirementsHash` field cannot neutralize a binding the recipient
signed.

### Hold-Invoice Griefing

Recipients using hold invoices can delay HTLC resolution, locking payer
liquidity. Clients SHOULD bound HTLC expiry deltas and treat excessive holds
as payment failure. Note that a hold invoice cannot produce a false proof —
the preimage only exists once the HTLC is actually accepted — so this is a
liveness concern, not a safety one.

### Fiat Quote Staleness

`fiatQuote` is informational. Agents applying fiat budgets MUST NOT treat it
as verified unless upgraded by a signed-oracle extension.

### Payer Privacy

Lightning payments do not reveal payer identity to the verifier;
implementations MUST NOT require payer identification at the scheme level.
Identity, where needed, belongs to extensions.

## Interoperability Notes

- **L402 (bLIP-0026).** Complementary: L402 grants a reusable authentication
  token after payment; this implementation treats each request as an
  independently settled payment. Servers MAY offer both (`WWW-Authenticate`
  for L402, the `accepts` array for x402).
- **BOLT12.** A `"bolt12"` asset transfer method would replace
  `extra.invoice` with `extra.offer`; the invoice fetched from the offer MUST
  satisfy the same binding and verification rules.

## References

- BOLT11 invoice protocol; BOLT12 offers
- RFC 8785 JSON Canonicalization Scheme
- CAIP-2 chain identifiers; `bip122` namespace
- bLIP-0026 (L402)
- Reference implementation: https://github.com/javierpmateos/x402-lightning
