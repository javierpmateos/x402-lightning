export interface CreateInvoiceParams {
  msat: bigint;
  descriptionHash: string; // hex, 32 bytes — the requirementsHash binding
  expirySeconds: number;
}

export interface CreatedInvoice {
  paymentRequest: string;
  paymentHash: string;
  createdAt: number;
}

/**
 * Backend abstraction so LND, CLN, or an Ark-style wallet API are
 * interchangeable (Mode B invoice issuance). Verification never requires a
 * backend; `lookupSettled` is optional defense-in-depth only.
 */
export interface LightningBackend {
  createInvoice(params: CreateInvoiceParams): Promise<CreatedInvoice>;
  lookupSettled?(paymentHash: string): Promise<boolean>;
}

/** LND REST backend. Requires LND_REST_URL and LND_MACAROON_HEX. */
export class LndBackend implements LightningBackend {
  constructor(private restUrl: string, private macaroonHex: string) {}

  async createInvoice(p: CreateInvoiceParams): Promise<CreatedInvoice> {
    const res = await fetch(`${this.restUrl}/v1/invoices`, {
      method: "POST",
      headers: { "Grpc-Metadata-macaroon": this.macaroonHex, "Content-Type": "application/json" },
      body: JSON.stringify({
        value_msat: p.msat.toString(),
        description_hash: Buffer.from(p.descriptionHash, "hex").toString("base64"),
        expiry: String(p.expirySeconds),
      }),
    });
    if (!res.ok) throw new Error(`lnd createInvoice failed: ${res.status}`);
    const body = (await res.json()) as { payment_request: string; r_hash: string };
    return {
      paymentRequest: body.payment_request,
      paymentHash: Buffer.from(body.r_hash, "base64").toString("hex"),
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  async lookupSettled(paymentHash: string): Promise<boolean> {
    const res = await fetch(`${this.restUrl}/v1/invoice/${paymentHash}`, {
      headers: { "Grpc-Metadata-macaroon": this.macaroonHex },
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { state?: string };
    return body.state === "SETTLED";
  }
}
