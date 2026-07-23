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
        scheme: "lightning",
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
 * VIC envelope — relays the invoice-commitment context so the client can pair
 * the fiscal document (committed via description_hash per the scheme spec) with
 * the settlement proof. Merkle batch anchoring accumulates commitments; the
 * anchor call to the EVM registrar is left to the operator's batching job.
 */
export function vicExtension(batch: VicBatchAccumulator): FacilitatorExtension {
  return {
    key: "vic",
    async enrichSettleResponse(ctx: SettleContext) {
      if (!ctx.result.success) return undefined;
      const commitment = ctx.requirements.extra.requirementsHash;
      if (!commitment) return undefined;
      const position = batch.add(commitment);
      return {
        _ext: { invoice: { commitment, paymentRef: { type: "lightning", paymentHash: ctx.paymentPayload.payload.paymentHash } } },
        anchoring: { mode: "merkle-batch", batchId: batch.id, position },
      };
    },
  };
}

export class VicBatchAccumulator {
  readonly id = createHash("sha256").update(String(Date.now())).digest("hex").slice(0, 16);
  private leaves: string[] = [];
  add(commitment: string): number {
    this.leaves.push(commitment);
    return this.leaves.length - 1;
  }
  /** Merkle root over accumulated commitments — anchor this in the registrar. */
  root(): string {
    let level: Buffer[] = this.leaves.map((l) => Buffer.from(l, "hex"));
    if (level.length === 0) return "";
    while (level.length > 1) {
      const next: Buffer[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const right = level[i + 1] ?? level[i];
        next.push(createHash("sha256").update(Buffer.concat([level[i], right])).digest());
      }
      level = next;
    }
    return level[0].toString("hex");
  }
}
