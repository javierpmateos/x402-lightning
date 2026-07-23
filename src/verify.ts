import bolt11 from "bolt11";
import { sha256Hex, computeRequirementsHash } from "./canonical.js";
import type { PaymentPayload, PaymentRequirements, VerifyResult } from "./types.js";
import type { SpentSet } from "./spentSet.js";

function tag(decoded: bolt11.PaymentRequestObject, name: string): unknown {
  return decoded.tags.find((t) => t.tagName === name)?.data;
}

function toMsat(req: PaymentRequirements): bigint {
  const amount = BigInt(req.amount);
  return req.extra.denomination === "sat" ? amount * 1000n : amount;
}

const HEX32 = /^[0-9a-f]{64}$/i;

export interface VerifyOptions {
  now?: number; // unix seconds, injectable for tests
}

/**
 * Implements Facilitator Verification Rules 1-8 of scheme_exact_lightning.
 * Rules 1-7 are pure functions of the inputs; rule 8 consults the spent-set.
 * Pass spentSet=null to run rules 1-7 only (/verify); /settle runs all eight.
 */
export async function verifyPayment(
  payload: PaymentPayload,
  req: PaymentRequirements,
  spentSet: SpentSet | null,
  opts: VerifyOptions = {}
): Promise<VerifyResult> {
  const now = opts.now ?? Date.now() / 1000;
  const p = payload.payload;
  const acc = payload.accepted;

  // Rule 1: envelope checks (x402 v2)
  if (payload.x402Version !== 2) {
    return { isValid: false, failedRule: 1, invalidReason: "unsupported x402Version" };
  }
  if (!acc || acc.scheme !== "exact" || req.scheme !== "exact") {
    return { isValid: false, failedRule: 1, invalidReason: "scheme must be exact" };
  }
  const topMatch =
    acc.network === req.network && acc.asset === req.asset && acc.payTo === req.payTo &&
    acc.amount === req.amount && acc.maxTimeoutSeconds === req.maxTimeoutSeconds;
  const extraMatch =
    acc.extra?.paymentMethod === "lightning" && req.extra.paymentMethod === "lightning" &&
    acc.extra?.denomination === req.extra.denomination &&
    acc.extra?.invoice === req.extra.invoice &&
    acc.extra?.paymentHash === req.extra.paymentHash;
  if (!topMatch || !extraMatch) {
    return { isValid: false, failedRule: 1, invalidReason: "accepted does not match paymentRequirements" };
  }

  // Rule 2: SHA-256(preimage) == paymentHash
  if (!HEX32.test(p.preimage) || !HEX32.test(p.paymentHash)) {
    return { isValid: false, failedRule: 2, invalidReason: "malformed preimage or payment hash" };
  }
  if (sha256Hex(Buffer.from(p.preimage, "hex")) !== p.paymentHash.toLowerCase()) {
    return { isValid: false, failedRule: 2, invalidReason: "preimage does not hash to payment hash" };
  }

  // Decode invoice once for rules 3-7.
  let decoded: bolt11.PaymentRequestObject;
  try {
    decoded = bolt11.decode(req.extra.invoice);
  } catch {
    return { isValid: false, failedRule: 3, invalidReason: "invoice decode failed" };
  }

  // Rule 3: invoice consistency
  const invoiceHash = String(tag(decoded, "payment_hash") ?? "").toLowerCase();
  if (invoiceHash !== p.paymentHash.toLowerCase() || invoiceHash !== req.extra.paymentHash.toLowerCase()) {
    return { isValid: false, failedRule: 3, invalidReason: "payment hash does not match invoice" };
  }

  // Rule 4: invoice signature recovers to payTo
  if ((decoded.payeeNodeKey ?? "").toLowerCase() !== req.payTo.toLowerCase()) {
    return { isValid: false, failedRule: 4, invalidReason: "invoice signer does not match payTo" };
  }

  // Rule 5: amounts compared in millisatoshi after decoding
  const invoiceMsat = decoded.millisatoshis ? BigInt(decoded.millisatoshis) : null;
  if (invoiceMsat === null || invoiceMsat !== toMsat(req)) {
    return { isValid: false, failedRule: 5, invalidReason: "invoice amount does not match requirements" };
  }

  // Rule 6: expiry
  const created = decoded.timestamp ?? 0;
  const expiry = Number(tag(decoded, "expire_time") ?? 3600);
  const expiresAt = created + expiry;
  if (now > expiresAt) {
    return { isValid: false, failedRule: 6, invalidReason: "invoice expired" };
  }
  if (now > created + req.maxTimeoutSeconds) {
    return { isValid: false, failedRule: 6, invalidReason: "proof presented after maxTimeoutSeconds" };
  }

  // Rule 7: requirements binding via description_hash
  if (req.extra.requirementsHash) {
    const commit = String(tag(decoded, "purpose_commit_hash") ?? "").toLowerCase();
    const expected = req.extra.requirementsHash.toLowerCase();
    if (commit !== expected) {
      return { isValid: false, failedRule: 7, invalidReason: "invoice description_hash does not match requirementsHash" };
    }
    if (computeRequirementsHash(req) !== expected) {
      return { isValid: false, failedRule: 7, invalidReason: "requirementsHash does not recompute from canonical requirements" };
    }
  }

  // Rule 8: single use
  if (spentSet) {
    const fresh = await spentSet.markSpent(invoiceHash, expiresAt);
    if (!fresh) {
      return { isValid: false, failedRule: 8, invalidReason: "proof already redeemed" };
    }
  }

  return { isValid: true };
}
