//! A tiny, dependency-free JSON value model, writer, and parser.
//!
//! Just enough JSON to serialize a [`crate::report::Report`] to a machine-readable
//! artifact and parse it back for a round-trip test. No `serde_json`. All parse
//! paths are total: malformed or truncated input returns [`JsonError`], never a
//! panic.
//!
//! Supported: objects, arrays, strings (with the common escapes), unsigned and
//! signed integers, `true`/`false`, and `null`. Floating point is intentionally
//! unsupported — the report model is integer-only.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    /// JSON `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// An integer (JSON numbers are constrained to integers here).
    Int(i128),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<JsonValue>),
    /// An object with insertion-independent key lookup.
    Object(BTreeMap<String, JsonValue>),
}

/// A JSON parse failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    /// Input ended before a complete value was read.
    #[error("unexpected end of input")]
    UnexpectedEnd,
    /// A structural or token error at the given byte offset.
    #[error("unexpected byte at offset {0}")]
    Unexpected(usize),
    /// A number could not be represented as an `i128`.
    #[error("number out of range at offset {0}")]
    NumberOutOfRange(usize),
    /// Trailing content after a complete top-level value.
    #[error("trailing content at offset {0}")]
    TrailingContent(usize),
    /// A required key was missing or had the wrong type during extraction.
    #[error("schema mismatch: {0}")]
    Schema(String),
}

impl JsonValue {
    /// Get a field of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(m) => m.get(key),
            _ => None,
        }
    }

    /// Interpret as a `u64` (non-negative integer).
    pub fn as_u64(&self) -> Result<u64, JsonError> {
        match self {
            JsonValue::Int(i) if *i >= 0 => {
                u64::try_from(*i).map_err(|_| JsonError::Schema("u64 overflow".into()))
            }
            _ => Err(JsonError::Schema("expected non-negative integer".into())),
        }
    }

    /// Interpret as a `bool`.
    pub fn as_bool(&self) -> Result<bool, JsonError> {
        match self {
            JsonValue::Bool(b) => Ok(*b),
            _ => Err(JsonError::Schema("expected bool".into())),
        }
    }

    /// Interpret as a string slice.
    pub fn as_str(&self) -> Result<&str, JsonError> {
        match self {
            JsonValue::Str(s) => Ok(s),
            _ => Err(JsonError::Schema("expected string".into())),
        }
    }

    /// Interpret as an array slice.
    pub fn as_array(&self) -> Result<&[JsonValue], JsonError> {
        match self {
            JsonValue::Array(a) => Ok(a),
            _ => Err(JsonError::Schema("expected array".into())),
        }
    }

    /// Required object field, or a schema error naming the key.
    pub fn field(&self, key: &str) -> Result<&JsonValue, JsonError> {
        self.get(key)
            .ok_or_else(|| JsonError::Schema(format!("missing field '{key}'")))
    }
}

/// Escape and quote a string into `out`.
fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// An append-only JSON object/array writer producing compact, stable output.
///
/// Object keys are emitted in the exact order the caller adds them, so a given
/// report value serializes to a byte-identical string on every run.
#[derive(Debug, Default)]
pub struct JsonWriter {
    buf: String,
}

impl JsonWriter {
    /// Create an empty writer.
    #[must_use]
    pub fn new() -> Self {
        JsonWriter { buf: String::new() }
    }

    /// Consume the writer, returning the JSON text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.buf
    }

    /// Append a bare integer value.
    #[must_use]
    pub fn int(mut self, v: i128) -> Self {
        let _ = write!(self.buf, "{v}");
        self
    }

    /// Append a JSON object built by `f`.
    #[must_use]
    pub fn write_object<F: FnOnce(ObjectWriter) -> ObjectWriter>(self, f: F) -> Self {
        f(ObjectWriter {
            w: self,
            first: true,
        })
        .finish()
    }

    /// Append a JSON array whose items are serialized by `f`.
    #[must_use]
    pub fn write_array<T, F: FnMut(JsonWriter, &T) -> JsonWriter>(
        mut self,
        items: &[T],
        mut f: F,
    ) -> Self {
        self.buf.push('[');
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                self.buf.push(',');
            }
            self = f(self, item);
        }
        self.buf.push(']');
        self
    }
}

/// Fluent writer for a single JSON object. Emits keys in call order, so a given
/// value serializes byte-identically on every run.
#[derive(Debug)]
pub struct ObjectWriter {
    w: JsonWriter,
    first: bool,
}

impl ObjectWriter {
    fn key(&mut self, k: &str) {
        if self.first {
            self.w.buf.push('{');
            self.first = false;
        } else {
            self.w.buf.push(',');
        }
        write_json_string(&mut self.w.buf, k);
        self.w.buf.push(':');
    }

    /// Write an unsigned/signed integer field.
    #[must_use]
    pub fn int_field(mut self, k: &str, v: i128) -> Self {
        self.key(k);
        let _ = write!(self.w.buf, "{v}");
        self
    }

    /// Write a boolean field.
    #[must_use]
    pub fn bool_field(mut self, k: &str, v: bool) -> Self {
        self.key(k);
        self.w.buf.push_str(if v { "true" } else { "false" });
        self
    }

    /// Write a string field.
    #[must_use]
    pub fn str_field(mut self, k: &str, v: &str) -> Self {
        self.key(k);
        write_json_string(&mut self.w.buf, v);
        self
    }

    /// Write an `Option<u64>` field as a number or JSON `null`.
    #[must_use]
    pub fn opt_u64_field(mut self, k: &str, v: Option<u64>) -> Self {
        self.key(k);
        match v {
            Some(n) => {
                let _ = write!(self.w.buf, "{n}");
            }
            None => self.w.buf.push_str("null"),
        }
        self
    }

    /// Write a nested-object field, built by `f`.
    #[must_use]
    pub fn object_field<F: FnOnce(ObjectWriter) -> ObjectWriter>(mut self, k: &str, f: F) -> Self {
        self.key(k);
        self.w = self.w.write_object(f);
        self
    }

    /// Write an array field whose items are serialized by `f`.
    #[must_use]
    pub fn array_field<T, F: FnMut(JsonWriter, &T) -> JsonWriter>(
        mut self,
        k: &str,
        items: &[T],
        f: F,
    ) -> Self {
        self.key(k);
        self.w = self.w.write_array(items, f);
        self
    }

    /// Finish the object, returning the underlying writer.
    #[must_use]
    fn finish(mut self) -> JsonWriter {
        if self.first {
            self.w.buf.push('{');
        }
        self.w.buf.push('}');
        self.w
    }
}

/// Parse a complete JSON document.
pub fn parse(input: &str) -> Result<JsonValue, JsonError> {
    let bytes = input.as_bytes();
    let mut p = Parser { bytes, pos: 0 };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != bytes.len() {
        return Err(JsonError::TrailingContent(p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Result<u8, JsonError> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or(JsonError::UnexpectedEnd)
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => Ok(JsonValue::Str(self.parse_string()?)),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(JsonError::Unexpected(self.pos)),
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.peek()? == b {
            self.pos += 1;
            Ok(())
        } else {
            Err(JsonError::Unexpected(self.pos))
        }
    }

    fn parse_literal(&mut self, lit: &[u8]) -> Result<(), JsonError> {
        let end = self.pos + lit.len();
        if self.bytes.get(self.pos..end) == Some(lit) {
            self.pos = end;
            Ok(())
        } else {
            Err(JsonError::Unexpected(self.pos))
        }
    }

    fn parse_bool(&mut self) -> Result<JsonValue, JsonError> {
        if self.peek()? == b't' {
            self.parse_literal(b"true")?;
            Ok(JsonValue::Bool(true))
        } else {
            self.parse_literal(b"false")?;
            Ok(JsonValue::Bool(false))
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, JsonError> {
        self.parse_literal(b"null")?;
        Ok(JsonValue::Null)
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        if self.peek()? == b'-' {
            self.pos += 1;
        }
        let digit_start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == digit_start {
            return Err(JsonError::Unexpected(start));
        }
        // Reject fractional/exponent forms: the model is integer-only.
        if matches!(
            self.bytes.get(self.pos),
            Some(b'.') | Some(b'e') | Some(b'E')
        ) {
            return Err(JsonError::Unexpected(self.pos));
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| JsonError::Unexpected(start))?;
        let n: i128 = text
            .parse()
            .map_err(|_| JsonError::NumberOutOfRange(start))?;
        Ok(JsonValue::Int(n))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut s = String::new();
        loop {
            let b = self.peek()?;
            self.pos += 1;
            match b {
                b'"' => return Ok(s),
                b'\\' => {
                    let esc = self.peek()?;
                    self.pos += 1;
                    match esc {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'b' => s.push('\u{0008}'),
                        b'f' => s.push('\u{000C}'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or(JsonError::UnexpectedEnd)?;
                            let hs = std::str::from_utf8(hex)
                                .map_err(|_| JsonError::Unexpected(self.pos))?;
                            let code = u32::from_str_radix(hs, 16)
                                .map_err(|_| JsonError::Unexpected(self.pos))?;
                            self.pos += 4;
                            s.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err(JsonError::Unexpected(self.pos - 1)),
                    }
                }
                // A raw control byte inside a string is invalid.
                0x00..=0x1F => return Err(JsonError::Unexpected(self.pos - 1)),
                _ => {
                    // Copy the (possibly multi-byte UTF-8) character.
                    s.push(char::from(b));
                }
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            let v = self.parse_value()?;
            items.push(v);
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(JsonError::Unexpected(self.pos)),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(JsonValue::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek()? != b'"' {
                return Err(JsonError::Unexpected(self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let val = self.parse_value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(map));
                }
                _ => return Err(JsonError::Unexpected(self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Lcg;

    #[test]
    fn round_trips_scalars() {
        assert_eq!(parse("true").unwrap(), JsonValue::Bool(true));
        assert_eq!(parse(" false ").unwrap(), JsonValue::Bool(false));
        assert_eq!(parse("null").unwrap(), JsonValue::Null);
        assert_eq!(parse("42").unwrap(), JsonValue::Int(42));
        assert_eq!(parse("-7").unwrap(), JsonValue::Int(-7));
        assert_eq!(parse("\"hi\\n\"").unwrap(), JsonValue::Str("hi\n".into()));
    }

    #[test]
    fn parses_nested_structure() {
        let v = parse(r#"{"a":[1,2,3],"b":{"c":true},"n":null}"#).unwrap();
        assert_eq!(v.field("a").unwrap().as_array().unwrap().len(), 3);
        assert!(v.field("b").unwrap().field("c").unwrap().as_bool().unwrap());
        assert_eq!(v.field("n").unwrap(), &JsonValue::Null);
    }

    #[test]
    fn writer_then_parse_round_trip() {
        let text = JsonWriter::new()
            .write_object(|o| {
                o.int_field("count", 3)
                    .str_field("name", "order-insertion")
                    .bool_field("ok", true)
                    .opt_u64_field("cycles", None)
                    .array_field("xs", &[1u64, 2, 3], |w, x| w.int(i128::from(*x)))
                    .object_field("inner", |io| io.int_field("z", 9))
            })
            .into_string();
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.field("count").unwrap().as_u64().unwrap(), 3);
        assert_eq!(
            parsed.field("name").unwrap().as_str().unwrap(),
            "order-insertion"
        );
        assert!(parsed.field("ok").unwrap().as_bool().unwrap());
        assert_eq!(parsed.field("cycles").unwrap(), &JsonValue::Null);
        assert_eq!(parsed.field("xs").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            parsed
                .field("inner")
                .unwrap()
                .field("z")
                .unwrap()
                .as_u64()
                .unwrap(),
            9
        );
    }

    #[test]
    fn rejects_malformed_without_panic() {
        for bad in &[
            "",
            "{",
            "[",
            "{\"a\":}",
            "tru",
            "12.5",
            "1e3",
            "\"unterminated",
            "[1,2",
            "{\"a\":1,}",
            "nul",
            "}",
        ] {
            assert!(parse(bad).is_err(), "expected error for {bad:?}");
        }
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut r = Lcg::new(0xF00D_1234);
        for _ in 0..5000 {
            let len = r.upto(64);
            let bytes = r.bytes(len);
            // Lossily interpret as text; the parser must be total either way.
            let s = String::from_utf8_lossy(&bytes);
            let _ = parse(&s);
        }
    }
}
