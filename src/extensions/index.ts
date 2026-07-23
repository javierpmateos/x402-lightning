import { createHash, createHmac } from "node:crypto";
import type { FacilitatorExtension, SettleContext } from "../types.js";

/**
 * Settlement Attestation Receipt (SAR) — facilitator-signed attestation that a
 * given payment hash was verified as settled. Placeholder signer: HMAC over the
 * canonical claim; swap for EIP-712 or BIP-340 per the SAR spec profile.
 */
export function sarExtension(signingKey: Buffer): FacilitatorExtension {
  return {
    key: "facilitator-attestation",
    async enrichSettleResponse(ctx: SettleContext) {
      if (!ctx.result.success) return undefined;
      const claim = {
        scheme: "upfront",
        network: ctx.requirements.network,
        paymentHash: ctx.paymentPayload.payload.paymentHash,
        resource: ctx.paymentPayload.resource?.url ?? null,
        attestedAt: Math.floor(Date.now() / 1000),
      };
      const signature = createHmac("sha256", signingKey).update(JSON.stringify(claim)).digest("hex");
      return { claim, signature, alg: "hmac-sha256-placeholder" };
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
