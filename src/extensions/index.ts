import { createHash, createHmac } from "node:crypto";
import canonicalize from "canonicalize";
import type { FacilitatorExtension, SettleContext } from "../types.js";

/**
 * Lightning settlement claim (draft) — a facilitator-signed statement that a
 * given payment hash was verified and consumed, carrying payment hash, amount,
 * payee, requirements commitment, observation time and redemption result. The
 * claim is canonicalized (RFC 8785) and signed with an HMAC placeholder purely
 * to demonstrate the hook.
 *
 * Scope of the underlying proof: a preimage proves knowledge of the secret for
 * a payee-signed invoice. It does not prove payer identity, settlement time, or
 * delivery. Amount, payee and resource are attested because Rule 7 verified
 * them against the recipient-signed binding — not because the preimage implies
 * them.
 *
 * NOTE: this is NOT a Settlement Attestation Receipt implementation. A real
 * SAR profile (x402-foundation/x402#1195) specifies Ed25519 signatures over
 * the JCS-canonical form, with that spec's defined field set (receipt_version,
 * receipt_id = SHA256(JCS(core_fields)), verdict, verifier_kid, sig_alg, ...)
 * and verifier key discovery via `.well-known/sar-keys.json`. Emitting that
 * form is future work; the key here (`facilitator-attestation`) matches the
 * example in the facilitator extension hook PR (#2339) and does not claim the
 * SAR namespace.
 */
export function attestationExtension(signingKey: Buffer): FacilitatorExtension {
  return {
    key: "facilitator-attestation",
    async enrichSettleResponse(ctx: SettleContext) {
      if (!ctx.result.success) return undefined;
      // Every attested field is authenticated: amount, payee, network and the
      // requirements commitment come from the recipient-signed invoice binding
      // verified in Rule 7; `resource` is covered by that same commitment.
      // `observedAt` is the facilitator's observation time, NOT a
      // Lightning-native settlement timestamp — Lightning does not provide one.
      const claim = {
        claimVersion: "0.1-draft",
        scheme: "upfront",
        network: ctx.requirements.network,
        paymentHash: ctx.paymentPayload.payload.paymentHash,
        amount: ctx.requirements.amount,
        denomination: ctx.requirements.extra.denomination,
        payee: ctx.requirements.payTo,
        requirementsCommitment: ctx.requirements.extra.requirementsHash,
        resource: ctx.paymentPayload.resource.url,
        observedAt: Math.floor(Date.now() / 1000),
        redemption: "verified-and-consumed",
      };
      const payload = canonicalize(claim);
      if (!payload) return undefined;
      const signature = createHmac("sha256", signingKey).update(payload).digest("hex");
      return { claim, signature, alg: "hmac-sha256-placeholder", canonicalization: "RFC8785" };
    },
  };
}

/**
 * Requirements-commitment receipt — relays the x402 payment-terms commitment
 * (the requirementsHash bound into the invoice's description_hash) paired with
 * the settlement proof reference, so clients can retain a portable record of
 * what terms the recipient signed for this payment.
 *
 * NOTE: this is NOT a VIC envelope. A true VIC profile would carry the
 * EIP-712 invoiceHash of a signed fiscal Invoice struct per ERC-8342 and use
 * the published `_ext.invoice` shape (schema_id, invoice_hash, chain_id,
 * registrar, payment_tx_ref). That profile is future work and depends on how
 * the ERC resolves non-EVM settlement references; this extension deliberately
 * uses its own namespace to avoid colliding with it.
 */
export function requirementsCommitmentExtension(batch: CommitmentBatchAccumulator): FacilitatorExtension {
  return {
    key: "x402-requirements-commitment",
    async enrichSettleResponse(ctx: SettleContext) {
      if (!ctx.result.success) return undefined;
      const commitment = ctx.requirements.extra.requirementsHash;
      if (!commitment) return undefined;
      const position = batch.add(commitment);
      return {
        commitment,
        paymentHash: ctx.paymentPayload.payload.paymentHash,
        aggregation: { mode: "merkle-batch-offchain", batchId: batch.id, position },
      };
    },
  };
}

/**
 * Off-chain Merkle accumulator over commitment hashes. Domain-separated
 * (0x00 leaf / 0x01 node prefixes) and odd nodes are promoted, not duplicated,
 * avoiding the duplicate-leaf ambiguity pattern (cf. CVE-2012-2459).
 * Anchoring of roots is an operator concern outside this library.
 */
export class CommitmentBatchAccumulator {
  readonly id = createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 16);
  private leaves: string[] = [];
  add(commitment: string): number {
    this.leaves.push(commitment);
    return this.leaves.length - 1;
  }
  root(): string {
    const LEAF = Buffer.from([0x00]);
    const NODE = Buffer.from([0x01]);
    let level: Buffer[] = this.leaves.map((l) =>
      createHash("sha256").update(Buffer.concat([LEAF, Buffer.from(l, "hex")])).digest()
    );
    if (level.length === 0) return "";
    while (level.length > 1) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 === level.length) { next.push(level[i]); continue; }
        next.push(createHash("sha256").update(Buffer.concat([NODE, level[i], level[i + 1]])).digest());
      }
      level = next;
    }
    return level[0].toString("hex");
  }
}
