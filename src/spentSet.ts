export interface SpentSet {
  /** Atomically marks paymentHash as spent. Returns false if already spent. */
  markSpent(paymentHash: string, expiresAt: number): Promise<boolean>;
}

/**
 * In-memory spent-set with lazy TTL eviction. Suitable for a single-instance
 * facilitator; production multi-instance deployments should back this with a
 * shared store (see spec: replay across facilitators).
 */
export class MemorySpentSet implements SpentSet {
  private spent = new Map<string, number>();
  constructor(private safetyMarginSeconds = 3600) {}

  async markSpent(paymentHash: string, expiresAt: number): Promise<boolean> {
    this.evict();
    if (this.spent.has(paymentHash)) return false;
    this.spent.set(paymentHash, expiresAt + this.safetyMarginSeconds);
    return true;
  }

  private evict(): void {
    const now = Date.now() / 1000;
    for (const [hash, until] of this.spent) {
      if (until < now) this.spent.delete(hash);
    }
  }
}
