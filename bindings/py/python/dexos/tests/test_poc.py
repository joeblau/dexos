"""Cross-language conformance: the python binding must reproduce, bit-for-bit,
the golden bytes in ``conformance/vectors.json`` — the shared Rust core is the
single source of truth and every language marshals through it.

Run against an installed build::

    maturin develop -m bindings/py/Cargo.toml --features extension-module
    pytest bindings/py/python/dexos/tests -q
"""

import json
from pathlib import Path

import pytest

import dexos

# tests -> dexos -> python -> py -> bindings -> <repo root>
_VECTORS_PATH = Path(__file__).resolve().parents[5] / "conformance" / "vectors.json"
VECTORS = json.loads(_VECTORS_PATH.read_text())
SEED = bytes.fromhex(VECTORS["seed_hex"])


def test_encode_get_market_request_matches_golden() -> None:
    vec = VECTORS["encode_get_market_request"]
    out = dexos.encode_get_market_request(
        vec["input"]["request_id"], vec["input"]["market_id"]
    )
    assert isinstance(out, bytes)
    assert out.hex() == vec["frame_hex"]


def test_ed25519_sign_matches_golden() -> None:
    vec = VECTORS["ed25519_sign"]
    out = dexos.ed25519_sign(SEED, vec["input"]["msg_utf8"].encode())
    assert isinstance(out, bytes)
    assert len(out) == 64
    assert out.hex() == vec["sig_hex"]


def test_ed25519_sign_rejects_wrong_length_seed() -> None:
    with pytest.raises(ValueError):
        dexos.ed25519_sign(b"\x00" * 31, b"dexos")


def test_sign_submit_order_matches_golden() -> None:
    vec = VECTORS["signed_submit_order"]
    out = dexos.sign_submit_order(
        SEED, vec["input"]["client_id"], vec["input"]["nonce"]
    )
    assert isinstance(out, dict)
    assert isinstance(out["signature"], bytes)
    assert out["preimage"].hex() == vec["preimage_hex"]
    assert out["signature"].hex() == vec["signature_hex"]
    assert out["command_hash"].hex() == vec["command_hash_hex"]
    assert out["framed_request"].hex() == vec["framed_request_hex"]


def test_amount_to_decimal_is_canonical_fixed_six_dp() -> None:
    decimal = VECTORS["amount_pin"]["decimal"]  # "1.000000"
    assert dexos.amount_to_decimal(decimal) == decimal
    assert dexos.amount_to_decimal("1") == "1.000000"
    assert dexos.amount_to_decimal("1.5") == "1.500000"


def test_amount_to_decimal_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        dexos.amount_to_decimal("not-a-number")
