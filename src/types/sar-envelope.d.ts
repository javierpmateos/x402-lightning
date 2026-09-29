// Minimal declarations for sar-envelope@0.1.0 (ships JS only).
// Only the helpers the settlement claim reuses are declared.
declare module "sar-envelope" {
  export interface KeyEntry {
    kid: string;
    pubkey: Uint8Array;
    alg: "Ed25519";
    raw: Record<string, unknown>;
  }
  export function canonicalize(value: unknown): Uint8Array;
  export function parseKeyRegistry(document: unknown): Map<string, KeyEntry>;
  export function resolveKey(registry: Map<string, KeyEntry>, kid: string): KeyEntry;
  export class UnknownKeyError extends Error {}
  export class UnsupportedAlgorithmError extends Error {}
}
