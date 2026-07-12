// Fixed-6dp money helpers, mirroring the single audited Rust converter in
// `dexos-sdk-core::convert` (which delegates to `types::format_amount` /
// `parse_amount`). Money is NEVER a JS `number`: the scaled integer is a
// `bigint` (i64 Price/Quantity/Ratio, i128 Amount), the human form a decimal
// `string`. All scales are 1_000_000 (6 fractional digits), matching the Rust
// AMOUNT_SCALE / PRICE_SCALE / QTY_SCALE / RATIO_SCALE constants.
//
// The wasm core is the source of truth; `test/poc.test.ts` cross-checks these
// pure-TS helpers against `amount_to_decimal` / `amount_from_decimal` so the two
// implementations can never drift.

export const AMOUNT_SCALE = 1_000_000n;
export const PRICE_SCALE = 1_000_000n;
export const QTY_SCALE = 1_000_000n;
export const RATIO_SCALE = 1_000_000n;

/** Number of fixed fractional digits carried on the wire (matches Rust). */
export const DECIMALS = 6;

const SCALE = 1_000_000n;

/**
 * Format a raw scaled integer as its canonical fixed-6dp decimal string.
 * Byte-for-byte identical to Rust `format_amount`: `1_500_000n` -> `"1.500000"`,
 * `-1n` -> `"-0.000001"`, `0n` -> `"0.000000"`.
 */
export function rawToDecimal(raw: bigint): string {
  const neg = raw < 0n;
  const abs = neg ? -raw : raw;
  const intPart = abs / SCALE;
  const fracPart = abs % SCALE;
  const frac = fracPart.toString().padStart(DECIMALS, "0");
  return `${neg ? "-" : ""}${intPart.toString()}.${frac}`;
}

/**
 * Parse a decimal string (up to 6 fractional digits) into its raw scaled
 * integer. Mirrors Rust `parse_amount`: `"1.5"` -> `1_500_000n`,
 * `"-0.000001"` -> `-1n`. Throws on more than 6 fractional digits or malformed
 * input.
 */
export function decimalToRaw(decimal: string): bigint {
  const m = /^(-)?(\d+)(?:\.(\d{1,6}))?$/.exec(decimal.trim());
  if (!m) {
    throw new Error(
      `invalid decimal amount (max 6 fractional digits): ${JSON.stringify(decimal)}`,
    );
  }
  const neg = m[1] === "-";
  const intDigits = m[2] as string;
  const fracDigits = (m[3] ?? "").padEnd(DECIMALS, "0");
  const raw = BigInt(intDigits) * SCALE + BigInt(fracDigits);
  return neg ? -raw : raw;
}

/**
 * A bigint-backed fixed-6dp scaled value. `Amount`, `Price`, `Quantity`, and
 * `Ratio` are the same shape (all scale 1e6); distinct classes give call sites
 * type-level intent without ever falling back to a lossy JS `number`.
 */
class Fixed6 {
  protected constructor(readonly raw: bigint) {}
  toDecimal(): string {
    return rawToDecimal(this.raw);
  }
  toString(): string {
    return rawToDecimal(this.raw);
  }
  /** Serialize as the canonical decimal string (never a JS number). */
  toJSON(): string {
    return rawToDecimal(this.raw);
  }
}

export class Amount extends Fixed6 {
  static fromRaw(raw: bigint): Amount {
    return new Amount(raw);
  }
  static fromDecimal(decimal: string): Amount {
    return new Amount(decimalToRaw(decimal));
  }
}

export class Price extends Fixed6 {
  static fromRaw(raw: bigint): Price {
    return new Price(raw);
  }
  static fromDecimal(decimal: string): Price {
    return new Price(decimalToRaw(decimal));
  }
}

export class Quantity extends Fixed6 {
  static fromRaw(raw: bigint): Quantity {
    return new Quantity(raw);
  }
  static fromDecimal(decimal: string): Quantity {
    return new Quantity(decimalToRaw(decimal));
  }
}

export class Ratio extends Fixed6 {
  static fromRaw(raw: bigint): Ratio {
    return new Ratio(raw);
  }
  static fromDecimal(decimal: string): Ratio {
    return new Ratio(decimalToRaw(decimal));
  }
}
