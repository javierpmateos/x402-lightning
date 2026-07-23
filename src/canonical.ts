import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import type { PaymentRequirements } from "./types.js";

export function sha256Hex(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * requirementsHash = SHA-256( JCS(requirements \ {extra.invoice, extra.requirementsHash}) )
 * Per spec section "Requirements binding (description_hash)".
 */
export function computeRequirementsHash(req: PaymentRequirements): string {
  const { invoice: _i, requirementsHash: _r, ...extraRest } = req.extra;
  const stripped = { ...req, extra: extraRest };
  const canonical = canonicalize(stripped);
  if (!canonical) throw new Error("canonicalization failed");
  return sha256Hex(canonical);
}
