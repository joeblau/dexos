//! Read-only RPC surface with explicit verification status.
//!
//! [`RpcRequest`] models both the read methods a light node serves and the
//! write / order-entry methods it must refuse. Read responses are
//! [`RpcResponse`] variants, each wrapping a [`VerifiedValue`] so the caller
//! always receives a [`Verification`] tag; write requests never produce a
//! response — [`RpcRequest::unsupported_op`] names the refusal. `RpcRequest`
//! is `serde`-serializable so it can be decoded from untrusted wire bytes via
//! `codec` without panicking.

use serde::{Deserialize, Serialize};

use types::Hash;

use crate::discovery::MarketAdvertisement;
use crate::error::UnsupportedOp;
use crate::sync::VerifiedTip;
use crate::verification::{Verification, VerifiedValue};

/// A light-node RPC request (read methods plus refused write methods).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcRequest {
    /// Read: the highest verified checkpoint for a shard.
    GetLatestCheckpoint {
        /// Target shard.
        shard: u16,
    },
    /// Read: verify an account leaf + proof against the verified root.
    GetAccountProof {
        /// Target shard.
        shard: u16,
        /// Account id.
        account: u32,
        /// Claimed leaf bytes.
        leaf: Vec<u8>,
        /// Inclusion proof.
        proof: Vec<Hash>,
    },
    /// Read: verify a market leaf + proof against the verified root.
    GetMarketProof {
        /// Target shard.
        shard: u16,
        /// Market id.
        market: u32,
        /// Claimed leaf bytes.
        leaf: Vec<u8>,
        /// Inclusion proof.
        proof: Vec<Hash>,
    },
    /// Read: the set of discovered markets (advertised, unverified).
    GetDiscoveredMarkets,
    /// Write: submit an order (refused).
    SubmitOrder,
    /// Write: cancel an order (refused).
    CancelOrder,
    /// Write: amend an order (refused).
    AmendOrder,
    /// Write: deposit funds (refused).
    Deposit,
    /// Write: withdraw funds (refused).
    Withdraw,
}

impl RpcRequest {
    /// Whether this is a write / control method a light node must refuse.
    #[must_use]
    pub fn is_write(&self) -> bool {
        self.unsupported_op().is_some()
    }

    /// The [`UnsupportedOp`] a write method maps to, or `None` for reads.
    #[must_use]
    pub fn unsupported_op(&self) -> Option<UnsupportedOp> {
        match self {
            RpcRequest::SubmitOrder => Some(UnsupportedOp::SubmitOrder),
            RpcRequest::CancelOrder => Some(UnsupportedOp::CancelOrder),
            RpcRequest::AmendOrder => Some(UnsupportedOp::AmendOrder),
            RpcRequest::Deposit => Some(UnsupportedOp::Deposit),
            RpcRequest::Withdraw => Some(UnsupportedOp::Withdraw),
            RpcRequest::GetLatestCheckpoint { .. }
            | RpcRequest::GetAccountProof { .. }
            | RpcRequest::GetMarketProof { .. }
            | RpcRequest::GetDiscoveredMarkets => None,
        }
    }
}

/// A read response. Every variant carries a [`Verification`] status via its
/// [`VerifiedValue`] payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcResponse {
    /// The highest verified checkpoint tip.
    LatestCheckpoint(VerifiedValue<VerifiedTip>),
    /// A verified (or stale / unverified) account leaf.
    AccountProof(VerifiedValue<Vec<u8>>),
    /// A verified (or stale / unverified) market leaf.
    MarketProof(VerifiedValue<Vec<u8>>),
    /// Discovered markets (always unverified advertisement metadata).
    DiscoveredMarkets(VerifiedValue<Vec<MarketAdvertisement>>),
}

impl RpcResponse {
    /// The verification status carried by this response.
    #[must_use]
    pub fn verification(&self) -> Verification {
        match self {
            RpcResponse::LatestCheckpoint(v) => v.verification(),
            RpcResponse::AccountProof(v) => v.verification(),
            RpcResponse::MarketProof(v) => v.verification(),
            RpcResponse::DiscoveredMarkets(v) => v.verification(),
        }
    }
}
