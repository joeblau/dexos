#![allow(unsafe_code)] // pyo3 macro expansion; this crate is a thin FFI shim only.
//! `dexos-sdk-py` — the pip/python binding for the DexOS client SDK.
//!
//! This crate is a THIN shim over [`dexos_sdk_core`]: every `#[pyfunction]` only
//! marshals arguments and moves bytes, then delegates to the shared Rust core.
//! No wire logic (framing, signing, decimal formatting) lives here — the core is
//! the single source of truth, and `conformance/vectors.json` pins the bytes
//! every binding must reproduce.
//!
//! Byte payloads cross the boundary as Python `bytes` (never `list[int]`); the
//! `i128` [`Amount`](dexos_sdk_core::Amount) money type crosses as a canonical
//! fixed-6dp decimal string through the core's single converter.

use std::collections::BTreeMap;

use dexos_sdk_core::{convert, poc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3_stub_gen::{define_stub_info_gatherer, derive::gen_stub_pyfunction};

/// Deterministic framed `GetMarket` request. Delegates entirely to the core's
/// single source of truth; the python crate never re-implements framing.
#[gen_stub_pyfunction]
#[pyfunction]
fn encode_get_market_request(
    py: Python<'_>,
    request_id: u64,
    market_id: u32,
) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &poc::encode_get_market_request(request_id, market_id))
}

/// Deterministic ed25519 signature over `msg` for the keypair derived from the
/// 32-byte `seed`. Raises `ValueError` if `seed` is not exactly 32 bytes.
#[gen_stub_pyfunction]
#[pyfunction]
fn ed25519_sign<'py>(
    py: Python<'py>,
    seed: &Bound<'_, PyBytes>,
    msg: &Bound<'_, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let seed = convert::bytes32(seed.as_bytes()).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &poc::ed25519_sign(&seed, msg.as_bytes())))
}

/// The SSoT control-signing round-trip for a fixed `SubmitOrder`: returns a dict
/// with the `preimage`, `signature`, `command_hash`, and full `framed_request`
/// as `bytes`. These are exactly the values that must never drift between
/// languages. Raises `ValueError` if `seed` is not 32 bytes.
#[gen_stub_pyfunction]
#[pyfunction]
fn sign_submit_order(
    py: Python<'_>,
    seed: &Bound<'_, PyBytes>,
    client_id: u64,
    nonce: u64,
) -> PyResult<BTreeMap<String, Py<PyBytes>>> {
    let seed = convert::bytes32(seed.as_bytes()).map_err(PyValueError::new_err)?;
    let signed = poc::sign_submit_order(&seed, client_id, nonce);
    let mut out = BTreeMap::new();
    out.insert(
        "preimage".to_string(),
        PyBytes::new(py, &signed.preimage).unbind(),
    );
    out.insert(
        "signature".to_string(),
        PyBytes::new(py, &signed.signature).unbind(),
    );
    out.insert(
        "command_hash".to_string(),
        PyBytes::new(py, &signed.command_hash).unbind(),
    );
    out.insert(
        "framed_request".to_string(),
        PyBytes::new(py, &signed.framed_request).unbind(),
    );
    Ok(out)
}

/// Canonicalize a decimal amount string through the core's single money
/// converter: parses `decimal` (max 6 fractional digits) into the `i128`
/// [`Amount`](dexos_sdk_core::Amount) and re-formats it fixed-6dp, e.g.
/// `"1.5"` -> `"1.500000"`. Raises `ValueError` on an invalid amount.
#[gen_stub_pyfunction]
#[pyfunction]
fn amount_to_decimal(decimal: &str) -> PyResult<String> {
    let amount = convert::amount_from_decimal(decimal).map_err(PyValueError::new_err)?;
    Ok(convert::amount_to_decimal(amount))
}

/// The `dexos._core` extension module: the compiled seam embedding the shared
/// Rust core. The ergonomic surface is re-exported by the pure-python `dexos`
/// package.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_get_market_request, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(sign_submit_order, m)?)?;
    m.add_function(wrap_pyfunction!(amount_to_decimal, m)?)?;
    Ok(())
}

// Gathers the `#[gen_stub_pyfunction]` inventory so `src/bin/stub_gen.rs` can
// write the committed, diff-gated `python/dexos/_core.pyi`. Per pyo3-stub-gen,
// this MUST live in the library crate (same crate as the inventory submissions),
// not in the generator binary.
define_stub_info_gatherer!(stub_info);
