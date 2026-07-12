//! The cross-language proof-of-correctness surface.
//!
//! These functions are the SSoT-critical logic every binding must reproduce
//! bit-for-bit: deterministic framing (types + codec + framing), deterministic
//! ed25519 signing (crypto), and — the load-bearing one — the control-signing
//! preimage + `command_hash` + signed `SubmitOrder` round-trip. The whole
//! architecture exists to pin these so they never drift between languages.

use crypto::KeyPair;
use proto::{command_hash, encode_request, ControlMeta, RpcMethod, RpcRequest, SubmitOrderParams};
use types::{AccountId, MarketId, OrderType, Price, Quantity, Ratio, Side, TimeInForce};

/// LOGIC #1 (types + codec + framing): deterministic framed `GetMarket` request.
///
/// Golden (verified by hand): `encode_get_market_request(1, 42)` ==
/// `05de010007010001000000000000000300000001032a`
/// (magic DE05, ver 1, class MarketData=7, msg_type 1, seq 1, plen 3,
/// payload `[01 03 2a]` = request_id 1, method index 3 GetMarket, MarketId 42).
pub fn encode_get_market_request(request_id: u64, market_id: u32) -> Vec<u8> {
    let req = RpcRequest::new(request_id, RpcMethod::GetMarket(MarketId::new(market_id)));
    encode_request(&req).expect("GetMarket framing is infallible")
}

/// LOGIC #2 (crypto): deterministic ed25519 signature (no RNG on the sign path).
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    KeyPair::from_seed(seed).sign(msg)
}

/// The control-signing preimage, its signature, the command hash, and the full
/// framed request produced by [`sign_submit_order`]. This is exactly what must
/// never drift between language bindings.
pub struct SignedSubmit {
    /// `"dexos.rpc.control.v1"` ++ postcard(signing payload).
    pub preimage: Vec<u8>,
    /// ed25519 signature over `preimage` (64 bytes).
    pub signature: Vec<u8>,
    /// Domain-tagged canonical hash of the lowered `Command` (32 bytes).
    pub command_hash: Vec<u8>,
    /// The full framed `RpcRequest` for the signed `SubmitOrder`.
    pub framed_request: Vec<u8>,
}

/// The single canonical `SubmitOrderParams` instance used by every golden
/// (the abi_freeze struct pin, [`sign_submit_order`], and `xtask gen-vectors`).
/// Defining it once keeps the Rust golden and the committed conformance vectors
/// from drifting apart.
pub fn golden_submit_params() -> SubmitOrderParams {
    SubmitOrderParams {
        account: AccountId::new(1),
        market: MarketId::new(42),
        side: Side::Bid,
        order_type: OrderType::Limit,
        price: Price::from_raw(2_500_000),
        quantity: Quantity::from_raw(4_000_000),
        time_in_force: TimeInForce::Gtc,
        leverage: Ratio::from_raw(1_000_000),
    }
}

/// LOGIC #3 (THE SSoT surface): the control-signing preimage + signature +
/// `command_hash` for a fixed `SubmitOrder`, plus its framed request.
pub fn sign_submit_order(seed: &[u8; 32], client_id: u64, nonce: u64) -> SignedSubmit {
    let kp = KeyPair::from_seed(seed);
    let params = golden_submit_params();
    let cmd = params.to_command();
    let meta = ControlMeta::signed(client_id, nonce, None, &kp, &cmd).expect("sign");
    // `ControlMeta` and `SubmitOrderParams` are `Copy`, so building the request
    // does not move `meta`/`params`; they are still usable below.
    let framed =
        encode_request(&RpcRequest::new(7, RpcMethod::SubmitOrder(meta, params))).expect("frame");
    SignedSubmit {
        preimage: meta.signing_bytes(&cmd).expect("preimage"),
        signature: meta.signature.to_vec(),
        command_hash: command_hash(&cmd).0.to_vec(),
        framed_request: framed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_market_matches_hand_computed_golden() {
        assert_eq!(
            hex::encode(encode_get_market_request(1, 42)),
            "05de010007010001000000000000000300000001032a"
        );
    }

    #[test]
    fn signed_submit_is_deterministic_and_verifies() {
        let a = sign_submit_order(&[7u8; 32], 1, 1);
        let b = sign_submit_order(&[7u8; 32], 1, 1);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.preimage, b.preimage);
        assert_eq!(a.command_hash, b.command_hash);
        assert_eq!(a.framed_request, b.framed_request);
        assert_eq!(a.signature.len(), 64);
        assert_eq!(a.command_hash.len(), 32);
        assert!(a.preimage.starts_with(b"dexos.rpc.control.v1"));

        // The signature actually verifies against the signer's public key over
        // the preimage — the round-trip is authentic, not merely stable.
        let kp = KeyPair::from_seed(&[7u8; 32]);
        let sig: [u8; 64] = a.signature.as_slice().try_into().unwrap();
        assert!(crypto::verify_ed25519(&kp.public(), &a.preimage, &sig).is_ok());
    }

    #[test]
    fn ed25519_sign_is_deterministic() {
        assert_eq!(
            ed25519_sign(&[7u8; 32], b"dexos"),
            ed25519_sign(&[7u8; 32], b"dexos")
        );
    }
}
