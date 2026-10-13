import bolt11 from "bolt11";
import {
  CLAIM_VERSION,
  CORE_FIELDS,
  canonicalCoreBytes,
  claimId,
  coreDigest,
  ed25519KeyFromSeed,
  extractCore,
  parseKeyRegistry,
  registryEntry,
  signClaim,
  verifyClaim,
  type ClaimCore,
  type SettlementClaim,
  type VerifyOptions,
} from "../src/settlement-claim/index.js";

let passed = 0;
let failed = 0;
function assert(name: string, cond: boolean) {
  if (cond) { passed++; console.log(`  ok  ${name}`); }
  else { failed++; console.log(`FAIL  ${name}`); }
}

// ---------------------------------------------------------------------------
// Deterministic inputs (all test-only, all independently published)

// RFC 8032 §7.1, TEST 1 secret key. Its public key is published there too.
const SEED = Buffer.from("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "hex");
const RFC8032_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

// scheme_exact_lnbtc.md test-vector invoice (receiver key 0x...01, created 1700000000).
const SPEC_INVOICE =
  "lnbc250n1pj48ugqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5p4nz8am4uqj4q8a87z3sk4x6yk4dv2mvel34epw68qqkwy0xcqvqxqzfvcqpjr4rx6ls6j5rpwknuea64evlk7yfx56wmqcer5eerekdsn9tlv6v4ex9mlz5dtm9qapl3svwlqcf7837dmjkru9z9w4h2rvm0md52w2sqxrwu5f";
const SPEC_PAYMENT_HASH = "a923c2c0e4fe77061ff1cb882171f6fdf926719bb7f5ffe2e05458438c52825e";
const SPEC_REQUEST_HASH = "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018";
const SPEC_PAYEE = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

const MAINNET = "lnbtc:000000000019d6689c085ae165831e93";
const TESTNET = "lnbtc:000000000933ea01ad0ee984209779ba";
const KID = "lnbtc-settlement-ed25519-01";

const { privateKey, x } = ed25519KeyFromSeed(SEED);
const registry = parseKeyRegistry({ keys: [registryEntry(KID, x)] });

const core: ClaimCore = {
  claim_version: CLAIM_VERSION,
  network: MAINNET,
  payment_hash: SPEC_PAYMENT_HASH,
  payment_request: SPEC_INVOICE,
  request_hash: SPEC_REQUEST_HASH,
  request_binding_profile: "http:1",
  observed_at: "2023-11-14T22:13:25Z", // 5 s after the invoice's creation time
  redemption: "verified-and-consumed",
  attester_kid: KID,
};
const claim = signClaim(core, privateKey);
const opts: VerifyOptions = { registry, expectedPayee: SPEC_PAYEE };

/** Build and validly sign a claim from a modified core: the attester itself is lying. */
const signedWith = (patch: Partial<ClaimCore>) => signClaim({ ...core, ...patch }, privateKey);
const failedAt = (c: Record<string, unknown>, o: VerifyOptions = opts) => {
  const r = verifyClaim(c, o);
  return r.ok ? "ok" : r.failed;
};

// ---------------------------------------------------------------------------
console.log("key and vector");

assert("seed reproduces the RFC 8032 TEST 1 public key", Buffer.from(x, "base64url").toString("hex") === RFC8032_PUB);
assert("valid claim over the spec invoice verifies", verifyClaim(claim, opts).ok);
const good = verifyClaim(claim, opts);
assert("verified payee is the invoice signer", good.ok && good.payee === SPEC_PAYEE);
assert("amount is read from the invoice, not the claim", good.ok && good.amountMsat === "25000");
assert("claim_id = sha256: + hex(SHA-256(JCS(core)))", claim.claim_id === claimId(core));
assert("signed core has exactly nine fields", Object.keys(JSON.parse(Buffer.from(canonicalCoreBytes(core)).toString("utf8"))).length === 9);
assert("verifies without an expected payee too", verifyClaim(claim, { registry }).ok);
assert("payeeChecked is true when an expected payee was compared", good.ok && good.payeeChecked === true);
assert("payeeChecked is false when no expected payee was supplied", (() => {
  const r = verifyClaim(claim, { registry });
  return r.ok && r.payeeChecked === false;
})());

// ---------------------------------------------------------------------------
console.log("\ntampering with a signed claim");

for (const f of CORE_FIELDS) {
  const t = { ...claim, [f]: f === "observed_at" ? "2023-11-14T22:13:26Z" : f === "payment_hash" || f === "request_hash" ? "00".repeat(32) : claim[f] + "x" };
  const r = failedAt(t);
  assert(`altered ${f} is rejected (${r})`, r !== "ok");
}

const relabeled = { ...claim, claim_version: "lnbtc.settlement.v2" };
assert("unknown claim_version rejected before anything else", failedAt(relabeled) === "claim_version");

// Recomputing claim_id after altering the core does not help: the signature
// covers the digest, so the old signature cannot be carried over.
const altered = { ...claim, observed_at: "2023-11-14T22:13:30Z" };
const recomputed = { ...altered, claim_id: claimId(extractCore(altered)) };
assert("altered core with recomputed claim_id fails the signature", failedAt(recomputed) === "signature");

assert("claim_id not matching the core is rejected", failedAt({ ...claim, claim_id: "sha256:" + "00".repeat(32) }) === "claim_id");
assert("sig_alg disagreeing with the resolved key is rejected", failedAt({ ...claim, sig_alg: "ES256K" }) === "sig_alg");
assert("unknown attester_kid is rejected", failedAt(signedWith({ attester_kid: "other-kid" })) === "key");
assert("sig without base64url: prefix is rejected", failedAt({ ...claim, sig: claim.sig.slice("base64url:".length) }) === "signature");
assert("signature from another key is rejected", (() => {
  const other = ed25519KeyFromSeed(Buffer.alloc(32, 7));
  return failedAt(signClaim(core, other.privateKey)) === "signature";
})());
assert("missing core field is rejected", (() => {
  const c = { ...claim } as Record<string, unknown>;
  delete c.request_binding_profile;
  return failedAt(c) === "shape";
})());
assert("unsigned extension fields do not change claim_id", verifyClaim({ ...claim, _ext: { note: "x" } }, opts).ok);

// ---------------------------------------------------------------------------
console.log("\nvalidly signed but contradicted by the invoice");

assert("payment_hash not matching the invoice", failedAt(signedWith({ payment_hash: "11".repeat(32) })) === "payment_hash");
assert("request_hash not matching the description hash", failedAt(signedWith({ request_hash: "22".repeat(32) })) === "request_hash");
assert("mainnet invoice under the testnet identifier", failedAt(signedWith({ network: TESTNET })) === "network");
assert("observed_at before the invoice was created", failedAt(signedWith({ observed_at: "2023-11-14T22:13:19Z" })) === "observed_at");
assert("invoice not signed by the expected payee", failedAt(claim, { registry, expectedPayee: "03" + "ab".repeat(32) }) === "payee");

// ---------------------------------------------------------------------------
console.log("\nformat rules (fail closed)");

assert("observed_at with fractional seconds", failedAt(signedWith({ observed_at: "2023-11-14T22:13:25.000Z" })) === "format");
assert("observed_at with an offset instead of Z", failedAt(signedWith({ observed_at: "2023-11-14T19:13:25-03:00" })) === "format");
assert("observed_at that is not a calendar time", failedAt(signedWith({ observed_at: "2023-02-30T10:00:00Z" })) === "format");
assert("unknown redemption value", failedAt(signedWith({ redemption: "verified" })) === "format");
assert("unknown request_binding_profile", failedAt(signedWith({ request_binding_profile: "http:2" })) === "format");
assert("uppercase hex payment_hash", failedAt(signedWith({ payment_hash: SPEC_PAYMENT_HASH.toUpperCase() })) === "format");
assert("unknown network", failedAt(signedWith({ network: "bip122:000000000019d6689c085ae165831e93" })) === "format");

// ---------------------------------------------------------------------------
console.log("\ntestnet path");

const tbNetwork = { bech32: "tb", pubKeyHash: 111, scriptHash: 196, validWitnessVersions: [0, 1] };
const nodeKey = "00".repeat(31) + "02";
const tbInvoice = bolt11.sign(
  bolt11.encode({
    network: tbNetwork,
    satoshis: 10,
    timestamp: 1700000000,
    tags: [
      { tagName: "payment_hash", data: "33".repeat(32) },
      { tagName: "payment_secret", data: "44".repeat(32) },
      { tagName: "purpose_commit_hash", data: SPEC_REQUEST_HASH },
      { tagName: "expire_time", data: 300 },
    ],
  }),
  nodeKey,
).paymentRequest!;
const tbClaim = signedWith({ network: TESTNET, payment_request: tbInvoice, payment_hash: "33".repeat(32) });
assert("testnet claim over a tb invoice verifies", verifyClaim(tbClaim, { registry }).ok);
assert("tb invoice under the mainnet identifier is rejected",
  failedAt(signedWith({ payment_request: tbInvoice, payment_hash: "33".repeat(32) }), { registry }) === "network");

const noDescHash = bolt11.sign(
  bolt11.encode({
    network: tbNetwork,
    satoshis: 10,
    timestamp: 1700000000,
    tags: [
      { tagName: "payment_hash", data: "33".repeat(32) },
      { tagName: "payment_secret", data: "44".repeat(32) },
      { tagName: "description", data: "plain description, no binding" },
    ],
  }),
  nodeKey,
).paymentRequest!;
assert("invoice without a description hash is rejected",
  failedAt(signedWith({ network: TESTNET, payment_request: noDescHash, payment_hash: "33".repeat(32) }), { registry }) === "request_hash");

// ---------------------------------------------------------------------------
// Signed-set negatives (published in the vector)
//
// The core is exactly CORE_FIELDS. These cases pin that membership, so an
// implementation that drops, renames or adds a member inside the core is
// caught by the vector itself, not only by reading the spec text.

/**
 * JCS bytes and digest of an arbitrary object, for cores that are not valid
 * ClaimCores (missing or extra members).
 */
function digestOf(obj: Record<string, string>) {
  const bytes = canonicalCoreBytes(obj as ClaimCore);
  return { canonical: Buffer.from(bytes).toString("utf8"), digest_hex: coreDigest(obj as ClaimCore).toString("hex") };
}

const validDigest = coreDigest(core).toString("hex");

// 1. claim_version mutated, claim_id recomputed, original signature kept.
const versionMutated = (version: string) => {
  const mutatedCore = { ...core, claim_version: version };
  const mutated = { ...claim, claim_version: version, claim_id: claimId(mutatedCore) };
  return { core: mutatedCore, claim: mutated };
};
const v2 = versionMutated("lnbtc.settlement.v2");
const v0 = versionMutated("lnbtc.settlement.v0");
assert("claim_version v2: digest differs from the valid core", coreDigest(v2.core).toString("hex") !== validDigest);
assert("claim_version v0: digest differs from the valid core", coreDigest(v0.core).toString("hex") !== validDigest);
assert("claim_version v2 is rejected", verifyClaim(v2.claim, opts).ok === false);
assert("claim_version v0 is rejected", verifyClaim(v0.claim, opts).ok === false);

// 2. A verifier that drops claim_version from the signed set computes a different digest.
const { claim_version: _dropped, ...withoutVersion } = core;
const dropped = digestOf(withoutVersion);
assert("core without claim_version: digest differs", dropped.digest_hex !== validDigest);

// 3. A member outside the core is not signed: adding one to the claim changes nothing,
//    while a verifier that pulls it into the signed set computes a different digest.
const EXTENSION = { x_example_extension: "not part of the core" };
const withExtension = { ...claim, ...EXTENSION };
assert("extension member outside the core: claim still verifies, same claim_id",
  verifyClaim(withExtension, opts).ok === true && withExtension.claim_id === claim.claim_id);
const absorbed = digestOf({ ...core, ...EXTENSION });
assert("extension member pulled into the core: digest differs", absorbed.digest_hex !== validDigest);

// ---------------------------------------------------------------------------
// Print the vector for #1195

if (process.argv.includes("--vector")) {
  const vec = {
    signing_key: { seed_hex: SEED.toString("hex"), source: "RFC 8032 §7.1 TEST 1", public_key_x: x },
    key_registry: { keys: [registryEntry(KID, x)] },
    core_fields: [...CORE_FIELDS],
    core_rule:
      "The signed core is exactly the members listed in core_fields, all non-empty strings, and no others. " +
      "claim_id, sig_alg, sig and any other member of the claim are outside it. Member order is not a separate " +
      "rule: JCS (RFC 8785) sorts members, so canonical_core is the JCS serialization of exactly these members.",
    core,
    canonical_core: Buffer.from(canonicalCoreBytes(core)).toString("utf8"),
    digest_hex: validDigest,
    claim: claim as SettlementClaim,
    negatives: [
      {
        name: "claim_version_v2",
        description:
          "claim_version changed to lnbtc.settlement.v2, claim_id recomputed over the mutated core, original sig kept. " +
          "MUST be rejected: unsupported version, and the signature does not cover the mutated digest.",
        digest_hex: coreDigest(v2.core).toString("hex"),
        claim: v2.claim,
        expect: "reject",
      },
      {
        name: "claim_version_v0",
        description: "As claim_version_v2, with lnbtc.settlement.v0.",
        digest_hex: coreDigest(v0.core).toString("hex"),
        claim: v0.claim,
        expect: "reject",
      },
      {
        name: "core_without_claim_version",
        description:
          "JCS over the core with claim_version removed. An implementation that drops claim_version from the " +
          "signed set computes this digest, which differs from digest_hex, so the signature does not verify.",
        canonical_core: dropped.canonical,
        digest_hex: dropped.digest_hex,
        expect: "digest_mismatch",
      },
      {
        name: "extension_member_outside_core",
        description:
          "The valid claim with an extra member added. The member is outside the core: the claim MUST still " +
          "verify, with the same claim_id.",
        claim: withExtension,
        expect: "accept",
      },
      {
        name: "extension_member_inside_core",
        description:
          "JCS over the core with that extra member pulled into it. An implementation that signs or verifies " +
          "over every member of the claim computes this digest, which differs from digest_hex.",
        canonical_core: absorbed.canonical,
        digest_hex: absorbed.digest_hex,
        expect: "digest_mismatch",
      },
    ],
  };
  console.log("\n" + JSON.stringify(vec, null, 2));
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
