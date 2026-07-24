import { createHash } from "node:crypto";
import canonicalize from "canonicalize";
import type { PaymentRequirements, ResourceInfo } from "./types.js";

export function sha256Hex(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * requirementsHash = SHA-256( JCS({ resource, requirements }) )
 *
 * The commitment covers BOTH the ResourceInfo from the PaymentRequired
 * envelope and the chosen PaymentRequirements entry (minus the invoice and
 * the hash field itself). Covering `resource` is what makes it authenticated:
 * it reaches the facilitator only through the client payload, so without this
 * a facilitator would be attesting to an unverified client-supplied value.
 * Because the invoice is signed by the recipient node key, this hash makes
 * the resource, price, network and terms all recipient-committed.
 */
export function computeRequirementsHash(req: PaymentRequirements, resource: ResourceInfo): string {
  const { invoice: _i, requirementsHash: _r, ...extraRest } = req.extra;
  const canonical = canonicalize({ resource, requirements: { ...req, extra: extraRest } });
  if (!canonical) throw new Error("canonicalization failed");
  return sha256Hex(canonical);
}
