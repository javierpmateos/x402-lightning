export type Network =
  | "bip122:000000000019d6689c085ae165831e93"
  | "bip122:00000008819873e925422c1ff0f99f7c"
  | "bip122:000000000933ea01ad0ee984209779ba";

export interface FiatQuote {
  amount: string;
  currency: string;
  rate: string;
  rateTimestamp: number;
}

export interface LightningRequirementsExtra {
  assetTransferMethod: "bolt11";
  denomination: "msat" | "sat";
  invoice: string;
  paymentHash: string;
  invoiceExpiry: number;
  requirementsHash?: string;
  fiatQuote?: FiatQuote;
  [key: string]: unknown;
}

export interface PaymentRequirements {
  scheme: "upfront";
  network: Network;
  amount: string;
  asset: "BTC";
  payTo: string;
  maxTimeoutSeconds: number;
  extra: LightningRequirementsExtra;
}

export interface ResourceInfo {
  url: string;
  description?: string;
  mimeType?: string;
}

export interface LightningPayload {
  paymentHash: string;
  preimage: string;
}

export interface PaymentPayload {
  x402Version: number;
  resource?: ResourceInfo;
  accepted: PaymentRequirements;
  payload: LightningPayload;
  extensions?: Record<string, unknown>;
}

export interface VerifyResult {
  isValid: boolean;
  invalidReason?: string;
  failedRule?: number;
}

export interface SettleResponse {
  success: boolean;
  network: Network;
  transaction: string | null;
  payer: null;
  errorReason?: string;
  extensions: Record<string, unknown>;
}

export interface SettleContext {
  paymentPayload: PaymentPayload;
  requirements: PaymentRequirements;
  result: SettleResponse;
}

export interface FacilitatorExtension {
  key: string;
  enrichSettleResponse?: (ctx: SettleContext) => Promise<unknown>;
}
