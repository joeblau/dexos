//! Writes `python/dexos/_core.pyi` from the `#[gen_stub_pyfunction]` items in the
//! library crate. Run in CI WITHOUT the `extension-module` feature so it links
//! libpython on the host and can execute:
//!
//! ```sh
//! cargo run -p dexos-sdk-py --bin stub_gen --locked
//! git diff --exit-code bindings/py/python/dexos/_core.pyi
//! ```
//!
//! The generated `.pyi` is committed and diff-gated: a change to the exported
//! function surface that isn't reflected in the stub fails the gate.

fn main() -> pyo3_stub_gen::Result<()> {
    let stub = dexos_sdk_py::stub_info()?;
    stub.generate()?;
    Ok(())
}
