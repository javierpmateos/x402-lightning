# x402-lightning

Reference facilitator for the x402 `upfront` scheme on Bitcoin Lightning,
under the payment-proof (client-settled) asset transfer family: the client
pays a BOLT11 invoice and presents the payment preimage as a self-verifying
proof of settlement.

- Spec draft: `specs/scheme_upfront_lightning.md` (target: `specs/schemes/upfront/`, pending x402-foundation/x402#2520)
- Stateless verification: rules 1-7 are pure functions of the request; only replay protection (rule 8) holds state
- Deterministic finality: the preimage *is* the settlement — no node query, no confirmation policy, no chain access
- `description_hash` binding: the BOLT11 invoice is a recipient-signed commitment to the canonical (RFC 8785) payment requirements
- Extensions via `enrichSettleResponse`: a facilitator attestation placeholder and a requirements-commitment receipt with off-chain Merkle aggregation
- Backends: LND REST included; interface allows CLN or Ark-style wallets

## Run tests
```
npm install
npm test
```

## Run the facilitator
```ts
import { LightningFacilitator } from "./src/facilitator.js";
new LightningFacilitator().listen(8402);
```
Endpoints: `POST /verify`, `POST /settle`, `GET /supported`.

## Scope notes

The two bundled extensions are illustrative consumers of the facilitator
extension pipeline, not implementations of published extension specs:

- `facilitator-attestation` signs a settlement claim with an HMAC placeholder.
  A real Settlement Attestation Receipt profile (x402-foundation/x402#1195)
  would emit that spec's canonical Ed25519 + JCS form with its defined field
  set — this is a hook demonstration, not a SAR implementation.
- `x402-requirements-commitment` relays the x402 payment-terms commitment
  bound into the invoice. It is not a Verifiable Invoice Commitment envelope:
  a VIC profile per ERC-8342 would carry the EIP-712 `invoiceHash` of a signed
  fiscal Invoice struct, and remains future work pending how that ERC resolves
  non-EVM settlement references.

Merkle aggregation of commitments is off-chain; anchoring roots is an operator
concern outside this library.
