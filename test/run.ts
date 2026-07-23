import { randomBytes, createHash } from "node:crypto";
import bolt11 from "bolt11";
import { computeRequirementsHash } from "../src/canonical.js";
import { verifyPayment } from "../src/verify.js";
import { MemorySpentSet } from "../src/spentSet.js";
import { LightningFacilitator } from "../src/facilitator.js";
import { attestationExtension, requirementsCommitmentExtension, CommitmentBatchAccumulator } from "../src/extensions/index.js";
import type { PaymentPayload, PaymentRequirements } from "../src/types.js";

let passed = 0;
let failed = 0;
function assert(name: string, cond: boolean) {
  if (cond) { passed++; console.log(`  ok  ${name}`); }
  else { failed++; console.log(`FAIL  ${name}`); }
}

const MAINNET = "bip122:000000000019d6689c085ae165831e93" as const;
const nodePriv = randomBytes(32);
const preimage = randomBytes(32);
const paymentHash = createHash("sha256").update(preimage).digest("hex");
const now = Math.floor(Date.now() / 1000);
const tbNetwork = { bech32: "tb", pubKeyHash: 111, scriptHash: 196, validWitnessVersions: [0, 1] };

const req: PaymentRequirements = {
  scheme: "upfront",
  network: MAINNET,
  amount: "1500",
  asset: "BTC",
  payTo: "",
  maxTimeoutSeconds: 3600,
  extra: {
    assetTransferMethod: "bolt11",
    denomination: "msat",
    invoice: "",
    paymentHash,
    invoiceExpiry: now + 3600,
    fiatQuote: { amount: "0.001", currency: "USD", rate: "65743.69", rateTimestamp: now },
  },
};

// Derive node pubkey via a throwaway signed invoice, then bind and sign the real one.
const probe = bolt11.sign(
  bolt11.encode({ network: tbNetwork, millisatoshis: "1500", timestamp: now,
    tags: [{ tagName: "payment_hash", data: paymentHash }, { tagName: "description", data: "probe" }] }),
  nodePriv.toString("hex")
);
req.payTo = bolt11.decode(probe.paymentRequest!).payeeNodeKey!;

const requirementsHash = computeRequirementsHash(req);
req.extra.requirementsHash = requirementsHash;

const signed = bolt11.sign(
  bolt11.encode({ network: tbNetwork, millisatoshis: "1500", timestamp: now,
    tags: [
      { tagName: "payment_hash", data: paymentHash },
      { tagName: "purpose_commit_hash", data: requirementsHash },
      { tagName: "expire_time", data: 3600 },
    ] }),
  nodePriv.toString("hex")
);
req.extra.invoice = signed.paymentRequest!;

function mkPayload(over: Partial<PaymentPayload["payload"]> = {}, accepted: PaymentRequirements = req): PaymentPayload {
  return {
    x402Version: 2,
    resource: { url: "https://api.example.com/v1/quote", mimeType: "application/json" },
    accepted,
    payload: { paymentHash, preimage: preimage.toString("hex"), ...over },
  };
}
const payload = mkPayload();

console.log("rules 1-7 (pure verification)");
assert("valid proof passes", (await verifyPayment(payload, req, null)).isValid);

const wrongVersion = { ...payload, x402Version: 1 };
assert("rule 1: wrong x402Version rejected", (await verifyPayment(wrongVersion, req, null)).failedRule === 1);

const tamperedAccepted = mkPayload({}, { ...req, amount: "9999" });
assert("rule 1: accepted mismatching requirements rejected", (await verifyPayment(tamperedAccepted, req, null)).failedRule === 1);

assert("rule 2: wrong preimage rejected", (await verifyPayment(mkPayload({ preimage: randomBytes(32).toString("hex") }), req, null)).failedRule === 2);

const otherPre = randomBytes(32);
const otherHash = createHash("sha256").update(otherPre).digest("hex");
assert("rule 3: hash not matching invoice rejected", (await verifyPayment(mkPayload({ paymentHash: otherHash, preimage: otherPre.toString("hex") }), req, null)).failedRule === 3);

const wrongSigner = { ...req, payTo: "02" + randomBytes(32).toString("hex") };
assert("rule 4: wrong signer rejected", (await verifyPayment(mkPayload({}, wrongSigner), wrongSigner, null)).failedRule === 4);

const wrongAmount = { ...req, amount: "2500" };
assert("rule 5: amount mismatch rejected (json vs invoice msat)", (await verifyPayment(mkPayload({}, wrongAmount), wrongAmount, null)).failedRule === 5);

assert("rule 6: expired invoice rejected", (await verifyPayment(payload, req, null, { now: now + 7200 })).failedRule === 6);

const tampered = { ...req, maxTimeoutSeconds: 7200, extra: { ...req.extra } };
assert("rule 7: tampered requirements break description_hash binding", (await verifyPayment(mkPayload({}, tampered), tampered, null)).failedRule === 7);

console.log("rule 8 (spent-set) + facilitator pipeline");
const facilitator = new LightningFacilitator(new MemorySpentSet());
facilitator.registerExtension(attestationExtension(randomBytes(32)));
const batch = new CommitmentBatchAccumulator();
facilitator.registerExtension(requirementsCommitmentExtension(batch));

const settle1 = await facilitator.settle(payload, req);
assert("settle succeeds with payment hash as transaction id", settle1.success && settle1.transaction === paymentHash);
assert("attestation extension attached on success", !!settle1.extensions["facilitator-attestation"]);
assert("requirements-commitment receipt carries commitment + payment hash",
  (settle1.extensions["x402-requirements-commitment"] as any)?.commitment === requirementsHash &&
  (settle1.extensions["x402-requirements-commitment"] as any)?.paymentHash === paymentHash);

const settle2 = await facilitator.settle(payload, req);
assert("rule 8: replay rejected on second settle", !settle2.success && settle2.errorReason === "proof already redeemed");
assert("extensions skip failed settlement (attestation guard)", settle2.extensions["facilitator-attestation"] === undefined);

assert("commitment batch produces a Merkle root", batch.root().length === 64);

// Fix regressions: rule 7 hardening + invoiceExpiry validation
const strippedBinding = { ...req, extra: { ...req.extra } } as PaymentRequirements;
delete (strippedBinding.extra as any).requirementsHash;
assert("rule 7: stripping requirementsHash alone still verifies (binding runs against signed invoice)",
  (await verifyPayment(mkPayload({}, strippedBinding), strippedBinding, null)).isValid);

const stripAndTamper = { ...strippedBinding, maxTimeoutSeconds: 7200, extra: { ...strippedBinding.extra } } as PaymentRequirements;
assert("rule 7: stripping requirementsHash cannot disable detection of tampered terms",
  (await verifyPayment(mkPayload({}, stripAndTamper), stripAndTamper, null)).failedRule === 7);

const badExpiry = { ...req, extra: { ...req.extra, invoiceExpiry: req.extra.invoiceExpiry + 999 } } as PaymentRequirements;
assert("rule 6: extra.invoiceExpiry must match the signed invoice", (await verifyPayment(mkPayload({}, badExpiry), badExpiry, null)).failedRule === 6);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
