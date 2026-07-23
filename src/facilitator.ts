import { createServer } from "node:http";
import { verifyPayment } from "./verify.js";
import { MemorySpentSet, type SpentSet } from "./spentSet.js";
import type {
  FacilitatorExtension,
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
} from "./types.js";

export class LightningFacilitator {
  private extensions: FacilitatorExtension[] = [];
  constructor(private spentSet: SpentSet = new MemorySpentSet()) {}

  registerExtension(ext: FacilitatorExtension): void {
    this.extensions.push(ext);
  }

  async verify(payload: PaymentPayload, req: PaymentRequirements) {
    // /verify runs checks 1-6 only; redemption (check 7) happens at /settle.
    return verifyPayment(payload, req, null);
  }

  async settle(payload: PaymentPayload, req: PaymentRequirements): Promise<SettleResponse> {
    const result = await verifyPayment(payload, req, this.spentSet);
    const settleResult: SettleResponse = result.isValid
      ? { success: true, network: req.network, transaction: payload.payload.paymentHash, payer: null, extensions: {} }
      : { success: false, network: req.network, transaction: null, payer: null, errorReason: result.invalidReason, extensions: {} };

    // Extension pipeline: mirrors x402 core FacilitatorExtension.enrichSettleResponse.
    // Error isolation — a failing extension MUST NOT break the payment.
    for (const ext of this.extensions) {
      if (!ext.enrichSettleResponse) continue;
      try {
        const data = await ext.enrichSettleResponse({ paymentPayload: payload, requirements: req, result: settleResult });
        if (data !== undefined) settleResult.extensions[ext.key] = data;
      } catch (err) {
        console.error(`extension ${ext.key} failed:`, err);
      }
    }
    return settleResult;
  }

  listen(port: number): void {
    const facilitator = this;
    createServer(async (httpReq, httpRes) => {
      const send = (code: number, body: unknown) => {
        httpRes.writeHead(code, { "Content-Type": "application/json" });
        httpRes.end(JSON.stringify(body));
      };
      if (httpReq.method === "GET" && httpReq.url === "/supported") {
        return send(200, { kinds: [{ scheme: "upfront", network: "bip122:000000000019d6689c085ae165831e93" }, { scheme: "upfront", network: "bip122:00000008819873e925422c1ff0f99f7c" }] });
      }
      if (httpReq.method !== "POST" || !["/verify", "/settle"].includes(httpReq.url ?? "")) {
        return send(404, { error: "not found" });
      }
      let raw = "";
      httpReq.on("data", (c) => (raw += c));
      httpReq.on("end", async () => {
        try {
          const { paymentPayload, paymentRequirements } = JSON.parse(raw);
          if (httpReq.url === "/verify") {
            return send(200, await facilitator.verify(paymentPayload, paymentRequirements));
          }
          return send(200, await facilitator.settle(paymentPayload, paymentRequirements));
        } catch (e) {
          return send(400, { error: "malformed request" });
        }
      });
    }).listen(port);
    console.log(`x402-lightning facilitator listening on :${port}`);
  }
}
