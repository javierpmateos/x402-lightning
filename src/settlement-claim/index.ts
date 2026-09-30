/**
 * Lightning settlement claim (lnbtc.settlement.v1).
 *
 * Implements the envelope posted on x402-foundation/x402#1195:
 *
 *   core      = the nine signed fields below
 *   digest    = SHA-256( JCS(core) )            (RFC 8785)
 *   claim_id  = "sha256:" + hex(digest)
 *   signature = Ed25519 over the 32 digest bytes (not over the JSON)
 *   sig       = "base64url:" + base64url(signature), unpadded
 *
 * `claim_id`, `sig_alg` and `sig` are outside the core. Key discovery reuses
 * sar-envelope's `parseKeyRegistry` / `resolveKey` against a registry with the
 * same shape as sar-keys.json.
 *
 * What the claim does and does not establish: everything except `redemption`
 * and `observed_at` is checked against the payee-signed BOLT11 invoice.
 * `redemption` (the preimage was consumed) lives in the attester's spent set
 * and rests on the attester's signature alone. `observed_at` is the attester's
 * statement of when it observed settlement; Lightning leaves no public
 * settlement timestamp, so the only independent bound is the invoice's
 * payee-signed creation time (observed_at MUST NOT precede it).
 */
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import bolt11 from "bolt11";
import { canonicalize, parseKeyRegistry, resolveKey } from "sar-envelope";
import type { KeyEntry } from "sar-envelope";

export const CLAIM_VERSION = "lnbtc.settlement.v1" as const;

export const CORE_FIELDS = [
  "claim_version",
  "network",
  "payment_hash",
  "payment_request",
  "request_hash",
  "request_binding_profile",
  "observed_at",
  "redemption",
  "attester_kid",
] as const;

export type CoreField = (typeof CORE_FIELDS)[number];
export type ClaimCore = Record<CoreField, string>;
export interface SettlementClaim extends ClaimCore {
  claim_id: string;
  sig_alg: string;
  sig: string;
  [extension: string]: unknown;
}

/** Concrete networks from scheme_exact_lnbtc.md, with their BOLT11 currency. */
export const NETWORK_CURRENCY: Readonly<Record<string, string>> = Object.freeze({
  "lnbtc:000000000019d6689c085ae165831e93": "bc", // mainnet
  "lnbtc:000000000933ea01ad0ee984209779ba": "tb", // testnet
});

export const REQUEST_BINDING_PROFILES = Object.freeze(["http:1", "mcp:1"]);

/** Only value defined for v1 in the #1195 envelope. Unknown values fail closed. */
export const REDEMPTION_VALUES = Object.freeze(["verified-and-consumed"]);

const HEX64 = /^[0-9a-f]{64}$/;
/** UTC, literal "Z", whole seconds — the single representation pinned in #1195. */
const OBSERVED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// ---------------------------------------------------------------------------
// Derivation

export function extractCore(claim: Record<string, unknown>): ClaimCore {
  const core = {} as ClaimCore;
  for (const f of CORE_FIELDS) {
    const v = claim[f];
    if (typeof v !== "string" || v.length === 0) {
      throw new Error(`core field ${f} must be a non-empty string`);
    }
    core[f] = v;
  }
  return core;
}

export function canonicalCoreBytes(core: ClaimCore): Uint8Array {
  return canonicalize(core);
}

export function coreDigest(core: ClaimCore): Buffer {
  return createHash("sha256").update(canonicalCoreBytes(core)).digest();
}

export function claimId(core: ClaimCore): string {
  return "sha256:" + coreDigest(core).toString("hex");
}

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// ---------------------------------------------------------------------------
// Keys

/** Ed25519 private key from a 32-byte seed (RFC 8032). */
export function ed25519KeyFromSeed(seed: Uint8Array) {
  if (seed.length !== 32) throw new Error("Ed25519 seed must be 32 bytes");
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  // Node accepts a private KeyObject here and derives its public half; the
  // bundled type definitions omit that overload.
  const publicKey = createPublicKey(privateKey as unknown as Parameters<typeof createPublicKey>[0]);
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return { privateKey, x: jwk.x };
}

/** Registry entry in the sar-keys.json shape. */
export function registryEntry(kid: string, x: string) {
  return { kid, kty: "OKP", crv: "Ed25519", x };
}

// ---------------------------------------------------------------------------
// Signing

export function signClaim(
  core: ClaimCore,
  privateKey: ReturnType<typeof createPrivateKey>,
): SettlementClaim {
  const digest = coreDigest(core);
  const signature = sign(null, digest, privateKey);
  return {
    ...core,
    claim_id: "sha256:" + digest.toString("hex"),
    sig_alg: "Ed25519",
    sig: "base64url:" + b64u(signature),
  };
}

// ---------------------------------------------------------------------------
// Verification

export type ClaimCheck =
  | "shape"
  | "claim_version"
  | "format"
  | "claim_id"
  | "key"
  | "sig_alg"
  | "signature"
  | "invoice"
  | "network"
  | "payment_hash"
  | "request_hash"
  | "observed_at"
  | "payee";

export type ClaimVerification =
  | {
      ok: true;
      claimId: string;
      /** Node key recovered from the invoice signature. */
      payee: string;
      /**
       * true only when `expectedPayee` was supplied and matched. When false,
       * the invoice was not attributed to the intended x402 payee: `ok` then
       * means the claim is authentic and consistent with a well-formed
       * invoice, not that the payment went to whom the caller intended.
       */
      payeeChecked: boolean;
      amountMsat: string | null;
      invoiceCreatedAt: number;
    }
  | { ok: false; failed: ClaimCheck; reason: string };

export interface VerifyOptions {
  /** Parsed key registry (sar-envelope parseKeyRegistry output). */
  registry: Map<string, KeyEntry>;
  /**
   * The payee the verifier expects (e.g. PaymentRequirements.payTo).
   * The invoice signature always recovers *a* node key; it only proves the
   * invoice came from the intended recipient when compared to an expected one.
   */
  expectedPayee?: string;
}

function fail(failed: ClaimCheck, reason: string): ClaimVerification {
  return { ok: false, failed, reason };
}

function invoiceTag(decoded: bolt11.PaymentRequestObject, name: string): unknown {
  return decoded.tags.find((t) => t.tagName === name)?.data;
}

export function verifyClaim(claim: Record<string, unknown>, opts: VerifyOptions): ClaimVerification {
  // 1. Shape
  let core: ClaimCore;
  try {
    core = extractCore(claim);
  } catch (e) {
    return fail("shape", (e as Error).message);
  }
  for (const f of ["claim_id", "sig_alg", "sig"] as const) {
    if (typeof claim[f] !== "string") return fail("shape", `${f} must be a string`);
  }

  // 2. Version first: it defines how everything else is interpreted.
  if (core.claim_version !== CLAIM_VERSION) {
    return fail("claim_version", `unsupported claim_version ${JSON.stringify(core.claim_version)}`);
  }

  // 3. Field formats
  if (!(core.network in NETWORK_CURRENCY)) return fail("format", `unsupported network ${core.network}`);
  if (!HEX64.test(core.payment_hash)) return fail("format", "payment_hash must be 64 lowercase hex");
  if (!HEX64.test(core.request_hash)) return fail("format", "request_hash must be 64 lowercase hex");
  if (!REQUEST_BINDING_PROFILES.includes(core.request_binding_profile)) {
    return fail("format", `unsupported request_binding_profile ${core.request_binding_profile}`);
  }
  if (!REDEMPTION_VALUES.includes(core.redemption)) {
    return fail("format", `unsupported redemption ${JSON.stringify(core.redemption)}`);
  }
  if (!OBSERVED_AT.test(core.observed_at) || Number.isNaN(Date.parse(core.observed_at))) {
    return fail("format", "observed_at must be UTC, 'Z', whole seconds (YYYY-MM-DDTHH:MM:SSZ)");
  }
  if (new Date(core.observed_at).toISOString().replace(".000Z", "Z") !== core.observed_at) {
    return fail("format", "observed_at is not a valid calendar time");
  }

  // 4. claim_id is derived, never trusted
  const digest = coreDigest(core);
  const expectedId = "sha256:" + digest.toString("hex");
  if (claim.claim_id !== expectedId) return fail("claim_id", "claim_id does not match the core digest");

  // 5. Key resolution; the algorithm is bound through the key
  let key: KeyEntry;
  try {
    key = resolveKey(opts.registry, core.attester_kid);
  } catch (e) {
    return fail("key", (e as Error).message);
  }
  if (claim.sig_alg !== key.alg) {
    return fail("sig_alg", `sig_alg ${JSON.stringify(claim.sig_alg)} disagrees with resolved key (${key.alg})`);
  }

  // 6. Signature over the 32 digest bytes
  const sigStr = claim.sig as string;
  if (!sigStr.startsWith("base64url:")) return fail("signature", "sig must be 'base64url:' prefixed");
  const sigBytes = Buffer.from(sigStr.slice("base64url:".length), "base64url");
  if (sigBytes.length !== 64) return fail("signature", "Ed25519 signature must be 64 bytes");
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: b64u(key.pubkey) },
    format: "jwk",
  });
  if (!verify(null, digest, publicKey, sigBytes)) return fail("signature", "signature does not verify");

  // 7. Everything the invoice can vouch for is read from the invoice
  let decoded: bolt11.PaymentRequestObject;
  try {
    decoded = bolt11.decode(core.payment_request);
  } catch (e) {
    return fail("invoice", `payment_request does not decode: ${(e as Error).message}`);
  }
  const payee = decoded.payeeNodeKey;
  if (!payee) return fail("invoice", "could not recover the payee node key from the invoice signature");

  if (decoded.network?.bech32 !== NETWORK_CURRENCY[core.network]) {
    return fail("network", `invoice currency ${decoded.network?.bech32} does not match ${core.network}`);
  }
  const invHash = String(invoiceTag(decoded, "payment_hash") ?? "").toLowerCase();
  if (invHash !== core.payment_hash) return fail("payment_hash", "payment_hash does not match the invoice");

  const commit = String(invoiceTag(decoded, "purpose_commit_hash") ?? "").toLowerCase();
  if (!commit) return fail("request_hash", "invoice carries no description hash");
  if (commit !== core.request_hash) return fail("request_hash", "request_hash does not match the invoice description hash");

  const createdAt = decoded.timestamp ?? 0;
  if (Date.parse(core.observed_at) / 1000 < createdAt) {
    return fail("observed_at", "observed_at precedes the invoice's payee-signed creation time");
  }

  if (opts.expectedPayee !== undefined && opts.expectedPayee.toLowerCase() !== payee.toLowerCase()) {
    return fail("payee", "invoice was not signed by the expected payee");
  }

  return {
    ok: true,
    claimId: expectedId,
    payee,
    payeeChecked: opts.expectedPayee !== undefined,
    amountMsat: decoded.millisatoshis ?? null,
    invoiceCreatedAt: createdAt,
  };
}

export { parseKeyRegistry };
