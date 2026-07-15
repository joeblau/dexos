/** Maximum number of executed batches whose finality may still arrive. */
export const MAX_PENDING_ORDER_BATCH_FINALITY = 65_536;

/** Internal bounded index for correlating late finality receipts. */
export class PendingFinalityCorrelations {
  readonly #capacity: number;
  readonly #keys = new Set<string>();

  constructor(capacity = MAX_PENDING_ORDER_BATCH_FINALITY) {
    if (!Number.isSafeInteger(capacity) || capacity <= 0) {
      throw new RangeError("pending finality capacity must be a positive safe integer");
    }
    this.#capacity = capacity;
  }

  get size(): number {
    return this.#keys.size;
  }

  get canRetain(): boolean {
    return this.#keys.size < this.#capacity;
  }

  retain(key: string): boolean {
    if (!this.canRetain || this.#keys.has(key)) return false;
    this.#keys.add(key);
    return true;
  }

  consume(key: string): boolean {
    return this.#keys.delete(key);
  }
}
