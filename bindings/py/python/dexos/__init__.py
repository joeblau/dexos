"""DexOS client SDK (python binding).

Thin, typed wrapper over the compiled ``dexos._core`` extension module, which
embeds the shared Rust core (``dexos-sdk-core``). Every function here delegates
to the core — no wire logic (framing, signing, decimal formatting) is
re-implemented in Python. The bytes each function returns are pinned by
``conformance/vectors.json`` and reproduced bit-for-bit across every language
binding.

Example::

    import dexos

    frame = dexos.encode_get_market_request(1, 42)
    signed = dexos.sign_submit_order(bytes([7]) * 32, client_id=1, nonce=1)
    sig = signed["signature"]  # 64-byte ed25519 signature
"""

from ._core import (
    amount_to_decimal,
    ed25519_sign,
    encode_get_market_request,
    sign_submit_order,
)

__all__ = [
    "amount_to_decimal",
    "ed25519_sign",
    "encode_get_market_request",
    "sign_submit_order",
]
