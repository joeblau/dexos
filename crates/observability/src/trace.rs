//! Distributed trace identifiers and a deterministic id generator.
//!
//! A [`TraceId`] is a 128-bit value (16 bytes) that stays stable for the life
//! of one command as it flows through every instrumented stage; a [`SpanId`] is
//! a 64-bit value identifying a single stage/operation within that trace.
//!
//! [`TraceGen`] is a `splitmix64`-based generator that is **fully deterministic
//! given its seed** — the same seed always yields the same id sequence, which
//! is what makes replay-based tests reproducible. It is intentionally not
//! cryptographic: ids are for correlation, not security.

/// A 128-bit distributed trace identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TraceId([u8; 16]);

impl TraceId {
    /// The all-zero trace id, treated as "no trace".
    pub const ZERO: TraceId = TraceId([0u8; 16]);

    /// Builds a trace id from a `u128` (big-endian byte order).
    #[must_use]
    pub const fn from_u128(v: u128) -> Self {
        Self(v.to_be_bytes())
    }

    /// Builds a trace id from raw bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// The raw 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The value as a `u128` (big-endian).
    #[must_use]
    pub const fn as_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// True if this is [`TraceId::ZERO`].
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Lower-case, zero-padded 32-char hex encoding.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(32);
        for byte in self.0 {
            s.push(hex_digit(byte >> 4));
            s.push(hex_digit(byte & 0x0f));
        }
        s
    }

    /// Parses a 32-char lower/upper hex string back into a trace id.
    ///
    /// # Errors
    /// Returns [`TraceParseError`] when the length is not 32 or a non-hex
    /// character is present. Never panics on arbitrary input.
    pub fn from_hex(s: &str) -> Result<Self, TraceParseError> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return Err(TraceParseError::BadLength);
        }
        let mut out = [0u8; 16];
        for (i, out_byte) in out.iter_mut().enumerate() {
            let hi = hex_val(bytes[i * 2])?;
            let lo = hex_val(bytes[i * 2 + 1])?;
            *out_byte = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

/// A 64-bit span identifier scoped to a single [`TraceId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SpanId(u64);

impl SpanId {
    /// The all-zero span id, treated as "no parent / no span".
    pub const ZERO: SpanId = SpanId(0);

    /// Builds a span id from a raw `u64`.
    #[must_use]
    pub const fn from_u64(v: u64) -> Self {
        Self(v)
    }

    /// The raw `u64`.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// True if this is [`SpanId::ZERO`].
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Deterministic `splitmix64`-based id generator.
///
/// Seeded once, it produces a fixed, reproducible stream of trace and span
/// ids. Not thread-safe by itself (it holds mutable state); share one per
/// thread, or protect it, for concurrent id minting.
#[derive(Debug, Clone)]
pub struct TraceGen {
    state: u64,
}

impl TraceGen {
    /// Creates a generator with the given seed.
    #[must_use]
    pub const fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Advances the internal state and returns the next 64-bit draw
    /// (`splitmix64`).
    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Mints a fresh, non-zero [`TraceId`] from two draws.
    pub fn new_trace(&mut self) -> TraceId {
        let hi = u128::from(self.next_u64());
        let lo = u128::from(self.next_u64());
        let mut v = (hi << 64) | lo;
        if v == 0 {
            v = 1;
        }
        TraceId::from_u128(v)
    }

    /// Mints a fresh, non-zero [`SpanId`] from one draw.
    pub fn new_span(&mut self) -> SpanId {
        let mut v = self.next_u64();
        if v == 0 {
            v = 1;
        }
        SpanId::from_u64(v)
    }

    /// Mints a fresh root [`TraceContext`] (new trace, new root span, no
    /// parent).
    pub fn new_context(&mut self) -> TraceContext {
        let trace = self.new_trace();
        let span = self.new_span();
        TraceContext {
            trace,
            span,
            parent: SpanId::ZERO,
        }
    }
}

/// A stable propagation context carried alongside a command: the trace id, the
/// current span, and the parent span. The `trace` field is what an observer
/// reads at each instrumented stage to correlate work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    /// Stable trace id for the whole command.
    pub trace: TraceId,
    /// Current span within the trace.
    pub span: SpanId,
    /// Parent span, or [`SpanId::ZERO`] for a root.
    pub parent: SpanId,
}

impl TraceContext {
    /// Derives a child context: same trace, a new span, parent = current span.
    pub fn child(&self, gen: &mut TraceGen) -> TraceContext {
        TraceContext {
            trace: self.trace,
            span: gen.new_span(),
            parent: self.span,
        }
    }
}

/// Error returned by [`TraceId::from_hex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TraceParseError {
    /// The input was not exactly 32 hex characters.
    #[error("trace id hex must be 32 characters")]
    BadLength,
    /// A non-hexadecimal character was encountered.
    #[error("trace id contains a non-hex character")]
    BadHexDigit,
}

#[must_use]
fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        _ => char::from(b'a' + (nibble - 10)),
    }
}

fn hex_val(c: u8) -> Result<u8, TraceParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(TraceParseError::BadHexDigit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_deterministic_for_a_seed() {
        let mut a = TraceGen::from_seed(0x1234_5678);
        let mut b = TraceGen::from_seed(0x1234_5678);
        for _ in 0..64 {
            assert_eq!(a.new_trace(), b.new_trace());
            assert_eq!(a.new_span(), b.new_span());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = TraceGen::from_seed(1);
        let mut b = TraceGen::from_seed(2);
        assert_ne!(a.new_trace(), b.new_trace());
    }

    #[test]
    fn ids_are_nonzero() {
        let mut g = TraceGen::from_seed(0);
        for _ in 0..100 {
            assert!(!g.new_trace().is_zero());
            assert!(!g.new_span().is_zero());
        }
    }

    #[test]
    fn hex_roundtrips() {
        let mut g = TraceGen::from_seed(99);
        let id = g.new_trace();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        assert_eq!(TraceId::from_hex(&hex).unwrap(), id);
    }

    #[test]
    fn from_hex_rejects_bad_input_without_panic() {
        assert_eq!(TraceId::from_hex(""), Err(TraceParseError::BadLength));
        assert_eq!(TraceId::from_hex("zz"), Err(TraceParseError::BadLength));
        let bad = "g".repeat(32);
        assert_eq!(TraceId::from_hex(&bad), Err(TraceParseError::BadHexDigit));
    }

    #[test]
    fn child_context_shares_trace_and_links_parent() {
        let mut g = TraceGen::from_seed(7);
        let root = g.new_context();
        assert_eq!(root.parent, SpanId::ZERO);
        let child = root.child(&mut g);
        assert_eq!(child.trace, root.trace);
        assert_eq!(child.parent, root.span);
        assert_ne!(child.span, root.span);
    }
}
