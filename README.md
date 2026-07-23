# x402-lightning

Reference facilitator for the x402 `upfront` scheme (payment-proof) on Bitcoin Lightning: Bitcoin Lightning as a
settlement rail for agentic pay-per-request payments, with verifiable invoice
commitments (VIC) and settlement attestations (SAR) via the facilitator
extension pipeline.

- Spec draft: `specs/scheme_upfront_lightning.md` (target: x402-foundation/x402 `specs/schemes/`)
- Stateless verification: rules 1-7 are pure; only replay protection (rule 8) holds state
- `description_hash` binding: the BOLT11 invoice is a recipient-signed commitment to the canonical (RFC 8785) payment requirements
- Extensions: SAR attestation + VIC envelope with Merkle batch anchoring, via `enrichSettleResponse`
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
