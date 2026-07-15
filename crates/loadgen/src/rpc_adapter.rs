//! Production signed-RPC adapter for live order traffic.
//!
//! Unlike the legacy private measured protocol, this adapter constructs the exact
//! `proto::RpcMethod::{SubmitOrder, CancelOrder, ReplaceOrder}` envelopes accepted by
//! DexOS, signs their canonical commands, correlates out-of-order responses, and only
//! exposes accepted order IDs to later cancel/replace actions.

use crypto::KeyPair;
use proto::{
    command_hash, CancelOrderParams, Command, CommandAck, ControlMeta, ReplaceOrderParams,
    RpcError, RpcMethod, RpcOk, RpcRequest, RpcResponse, SubmitOrderParams,
};
use types::{AccountId, MarketId, OrderId, Ratio, TimeInForce};

use crate::command::{CommandKind, GeneratedCommand};

/// Fixed identity and bounds for one persistent RPC session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcSessionConfig {
    /// Funded account authorized by `signing_seed`.
    pub account: AccountId,
    /// Globally partitioned client identifier.
    pub client_id: u64,
    /// First nonce in this assignment's disjoint namespace.
    pub nonce_base: u64,
    /// Deterministic ed25519 seed. Production callers load this from external secrets.
    pub signing_seed: [u8; 32],
    /// Maximum correlated requests allowed in flight on this connection.
    pub max_in_flight: usize,
    /// Maximum accepted live orders retained for valid cancels/replacements.
    pub max_live_orders: usize,
}

impl RpcSessionConfig {
    fn validate(self) -> Result<(), RpcAdapterError> {
        if self.max_in_flight == 0 || self.max_live_orders == 0 {
            return Err(RpcAdapterError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveOrder {
    id: OrderId,
    market: MarketId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingEffect {
    Add { market: MarketId },
    Remove { order: LiveOrder },
    Replace { order: LiveOrder },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRequest {
    request_id: u64,
    command_hash: types::Hash,
    effect: PendingEffect,
}

/// Outcome of correlating one production RPC response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterOutcome {
    /// Command was accepted and its acknowledgement was cryptographically bound to
    /// the exact command sent.
    Accepted(CommandAck),
    /// Validator returned a typed protocol rejection.
    Rejected(RpcError),
}

/// Per-connection stateful signed RPC adapter.
pub struct RpcSessionAdapter {
    config: RpcSessionConfig,
    keypair: KeyPair,
    next_nonce: u64,
    live_orders: Vec<LiveOrder>,
    next_live_replacement: usize,
    pending: Vec<PendingRequest>,
}

impl RpcSessionAdapter {
    /// Preallocate all bounded state for one session.
    pub fn new(config: RpcSessionConfig) -> Result<Self, RpcAdapterError> {
        config.validate()?;
        Ok(Self {
            config,
            keypair: KeyPair::from_seed(&config.signing_seed),
            next_nonce: config.nonce_base,
            live_orders: Vec::with_capacity(config.max_live_orders),
            next_live_replacement: 0,
            pending: Vec::with_capacity(config.max_in_flight),
        })
    }

    /// Public key whose account/session authorization must pass preflight.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public()
    }

    /// Globally partitioned client identifier used for request-ID construction.
    #[must_use]
    pub const fn client_id(&self) -> u64 {
        self.config.client_id
    }

    /// Number of requests awaiting a response.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Number of accepted orders available for later lifecycle actions.
    #[must_use]
    pub fn live_order_count(&self) -> usize {
        self.live_orders.len()
    }

    /// Build and sign an exact production request, enforcing the in-flight bound.
    ///
    /// Cancel/replace requests ignore generator-side speculative IDs and select only
    /// previously acknowledged orders. When no accepted order exists, the action is
    /// deterministically lowered to a new order instead of emitting an invalid cancel.
    pub fn build_request(
        &mut self,
        request_id: u64,
        generated: &GeneratedCommand,
    ) -> Result<RpcRequest, RpcAdapterError> {
        if self.pending.len() >= self.config.max_in_flight {
            return Err(RpcAdapterError::InFlightFull);
        }
        if self
            .pending
            .iter()
            .any(|pending| pending.request_id == request_id)
        {
            return Err(RpcAdapterError::DuplicateRequestId);
        }
        let nonce = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(RpcAdapterError::NonceExhausted)?;

        let (method, effect, command) = match generated.kind {
            CommandKind::NewOrder => self.new_order(generated, nonce)?,
            CommandKind::Cancel => match self.select_live(generated) {
                Some(order) => self.cancel_order(order, nonce)?,
                None => self.new_order(generated, nonce)?,
            },
            CommandKind::Replace => match self.select_live(generated) {
                Some(order) => self.replace_order(order, generated, nonce)?,
                None => self.new_order(generated, nonce)?,
            },
        };
        let expected_hash = command_hash(&command);
        self.pending.push(PendingRequest {
            request_id,
            command_hash: expected_hash,
            effect,
        });
        Ok(RpcRequest::new(request_id, method))
    }

    /// Correlate an out-of-order response and update live-order state only on a valid
    /// accepted acknowledgement.
    pub fn apply_response(
        &mut self,
        response: RpcResponse,
    ) -> Result<AdapterOutcome, RpcAdapterError> {
        let position = self
            .pending
            .iter()
            .position(|pending| pending.request_id == response.request_id)
            .ok_or(RpcAdapterError::UnknownResponse)?;
        let pending = self.pending.swap_remove(position);
        let ack = match response.result {
            Ok(RpcOk::CommandAck(ack)) => ack,
            Ok(_) => return Err(RpcAdapterError::WrongResponseType),
            Err(error) => return Ok(AdapterOutcome::Rejected(error)),
        };
        if ack.command_hash != pending.command_hash {
            return Err(RpcAdapterError::AckCommandMismatch);
        }

        match pending.effect {
            PendingEffect::Add { market } => {
                let order_id = ack.order_id.ok_or(RpcAdapterError::MissingOrderId)?;
                if ack.market_id != Some(market) {
                    return Err(RpcAdapterError::AckMarketMismatch);
                }
                let order = LiveOrder {
                    id: order_id,
                    market,
                };
                if self.live_orders.len() < self.config.max_live_orders {
                    self.live_orders.push(order);
                } else {
                    // This table is a bounded sample used to issue valid lifecycle
                    // actions, not a mirror of all validator state. Forgetting an old
                    // live order is safe; overwriting in place preserves fixed memory
                    // and avoids making a long open-loop run capacity-dependent.
                    let index = self.next_live_replacement % self.live_orders.len();
                    self.live_orders[index] = order;
                    self.next_live_replacement = (index + 1) % self.live_orders.len();
                }
            }
            PendingEffect::Remove { order } => {
                self.remove_live(order)?;
            }
            PendingEffect::Replace { order } => {
                let replacement = ack.order_id.unwrap_or(order.id);
                if ack.market_id != Some(order.market) {
                    return Err(RpcAdapterError::AckMarketMismatch);
                }
                let current = self
                    .live_orders
                    .iter_mut()
                    .find(|candidate| **candidate == order)
                    .ok_or(RpcAdapterError::StaleAcknowledgement)?;
                current.id = replacement;
            }
        }
        Ok(AdapterOutcome::Accepted(ack))
    }

    fn new_order(
        &self,
        generated: &GeneratedCommand,
        nonce: u64,
    ) -> Result<(RpcMethod, PendingEffect, Command), RpcAdapterError> {
        let params = SubmitOrderParams {
            account: self.config.account,
            market: generated.market,
            side: generated.side,
            order_type: generated.order_type,
            price: generated.price,
            quantity: generated.quantity,
            time_in_force: TimeInForce::Gtc,
            leverage: Ratio::from_raw(types::RATIO_SCALE),
        };
        let command = params.to_command();
        let meta = self.sign(nonce, &command)?;
        Ok((
            RpcMethod::SubmitOrder(meta, params),
            PendingEffect::Add {
                market: generated.market,
            },
            command,
        ))
    }

    fn cancel_order(
        &self,
        order: LiveOrder,
        nonce: u64,
    ) -> Result<(RpcMethod, PendingEffect, Command), RpcAdapterError> {
        let params = CancelOrderParams {
            account: self.config.account,
            market: order.market,
            order_id: order.id,
        };
        let command = params.to_command();
        let meta = self.sign(nonce, &command)?;
        Ok((
            RpcMethod::CancelOrder(meta, params),
            PendingEffect::Remove { order },
            command,
        ))
    }

    fn replace_order(
        &self,
        order: LiveOrder,
        generated: &GeneratedCommand,
        nonce: u64,
    ) -> Result<(RpcMethod, PendingEffect, Command), RpcAdapterError> {
        let params = ReplaceOrderParams {
            account: self.config.account,
            market: order.market,
            order_id: order.id,
            new_price: generated.price,
            new_quantity: generated.quantity,
        };
        let command = params.to_command();
        let meta = self.sign(nonce, &command)?;
        Ok((
            RpcMethod::ReplaceOrder(meta, params),
            PendingEffect::Replace { order },
            command,
        ))
    }

    fn sign(&self, nonce: u64, command: &Command) -> Result<ControlMeta, RpcAdapterError> {
        ControlMeta::signed(self.config.client_id, nonce, None, &self.keypair, command)
            .map_err(RpcAdapterError::Protocol)
    }

    fn select_live(&self, generated: &GeneratedCommand) -> Option<LiveOrder> {
        generated
            .target_order
            .and_then(|id| {
                self.live_orders.iter().copied().find(|order| {
                    order.id == id
                        && order.market == generated.market
                        && !self.order_is_reserved(*order)
                })
            })
            .or_else(|| {
                self.live_orders
                    .iter()
                    .copied()
                    .find(|order| !self.order_is_reserved(*order))
            })
    }

    fn order_is_reserved(&self, order: LiveOrder) -> bool {
        self.pending.iter().any(|pending| {
            matches!(
                pending.effect,
                PendingEffect::Remove { order: reserved }
                    | PendingEffect::Replace { order: reserved }
                    if reserved == order
            )
        })
    }

    fn remove_live(&mut self, order: LiveOrder) -> Result<(), RpcAdapterError> {
        let position = self
            .live_orders
            .iter()
            .position(|candidate| *candidate == order)
            .ok_or(RpcAdapterError::StaleAcknowledgement)?;
        self.live_orders.swap_remove(position);
        Ok(())
    }
}

/// Typed adapter or correlation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcAdapterError {
    /// Zero in-flight or live-order capacity.
    #[error("invalid RPC session capacity")]
    InvalidConfig,
    /// Configured in-flight depth has been reached.
    #[error("RPC in-flight table is full")]
    InFlightFull,
    /// Request ID is already pending on this connection.
    #[error("duplicate in-flight request id")]
    DuplicateRequestId,
    /// Disjoint nonce namespace was exhausted.
    #[error("RPC nonce namespace exhausted")]
    NonceExhausted,
    /// Response does not correlate to a pending request.
    #[error("unknown RPC response id")]
    UnknownResponse,
    /// Control request received a non-command success payload.
    #[error("wrong RPC response type")]
    WrongResponseType,
    /// Acknowledgement hash does not match the sent command.
    #[error("acknowledgement command hash mismatch")]
    AckCommandMismatch,
    /// Submit acknowledgement omitted its resulting order ID.
    #[error("submit acknowledgement omitted order id")]
    MissingOrderId,
    /// Acknowledgement market does not match the sent command.
    #[error("acknowledgement market mismatch")]
    AckMarketMismatch,
    /// An acknowledgement refers to state that is no longer live.
    #[error("stale order acknowledgement")]
    StaleAcknowledgement,
    /// Signing or protocol lowering failed.
    #[error("RPC protocol error: {0}")]
    Protocol(RpcError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{encode_request, FinalityStatus};
    use types::{OrderType, Price, Quantity, Side};

    fn adapter(client_id: u64, nonce_base: u64) -> RpcSessionAdapter {
        RpcSessionAdapter::new(RpcSessionConfig {
            account: AccountId::new(7),
            client_id,
            nonce_base,
            signing_seed: [3; 32],
            max_in_flight: 4,
            max_live_orders: 8,
        })
        .unwrap()
    }

    fn generated(kind: CommandKind, market: u32) -> GeneratedCommand {
        GeneratedCommand {
            session: 1,
            nonce: 0,
            idempotency_key: 1,
            market: MarketId::new(market),
            kind,
            side: Side::Bid,
            order_type: OrderType::Limit,
            price: Price::from_raw(10_000_000),
            quantity: Quantity::from_raw(1_000_000),
            target_order: None,
        }
    }

    fn accepted(request: &RpcRequest, order_id: Option<u64>) -> RpcResponse {
        let command = request.method.to_command().unwrap();
        let market = match command {
            Command::PlaceOrder { market, .. }
            | Command::CancelOrder { market, .. }
            | Command::ReplaceOrder { market, .. } => Some(market),
            _ => None,
        };
        RpcResponse::new(
            request.request_id,
            Ok(RpcOk::CommandAck(CommandAck {
                command_hash: command_hash(&command),
                finality: FinalityStatus::Accepted,
                order_id: order_id.map(OrderId::new),
                market_id: market,
            })),
        )
    }

    #[test]
    fn builds_real_signed_production_frames() {
        let mut adapter = adapter(10, 1_000);
        let request = adapter
            .build_request(99, &generated(CommandKind::NewOrder, 2))
            .unwrap();
        let RpcMethod::SubmitOrder(meta, params) = &request.method else {
            panic!("expected submit")
        };
        assert_eq!(meta.client_id, 10);
        assert_eq!(meta.nonce, 1_000);
        meta.verify_signature(&params.to_command()).unwrap();
        let bytes = encode_request(&request).unwrap();
        let decoded = proto::decode_request(&bytes).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn only_acknowledged_orders_drive_cancel_and_replace() {
        let mut adapter = adapter(10, 1_000);
        // No accepted live order: a requested cancel becomes a valid submit.
        let submit = adapter
            .build_request(1, &generated(CommandKind::Cancel, 3))
            .unwrap();
        assert!(matches!(submit.method, RpcMethod::SubmitOrder(..)));
        adapter.apply_response(accepted(&submit, Some(44))).unwrap();
        assert_eq!(adapter.live_order_count(), 1);

        // Generated market/ID speculation is ignored; the accepted market/order wins.
        let replace = adapter
            .build_request(2, &generated(CommandKind::Replace, 99))
            .unwrap();
        let RpcMethod::ReplaceOrder(_, params) = &replace.method else {
            panic!("expected replace")
        };
        assert_eq!(params.market, MarketId::new(3));
        assert_eq!(params.order_id, OrderId::new(44));
        adapter
            .apply_response(accepted(&replace, Some(45)))
            .unwrap();

        let cancel = adapter
            .build_request(3, &generated(CommandKind::Cancel, 88))
            .unwrap();
        let RpcMethod::CancelOrder(_, params) = &cancel.method else {
            panic!("expected cancel")
        };
        assert_eq!(params.market, MarketId::new(3));
        assert_eq!(params.order_id, OrderId::new(45));
        adapter.apply_response(accepted(&cancel, None)).unwrap();
        assert_eq!(adapter.live_order_count(), 0);
    }

    #[test]
    fn out_of_order_responses_correlate_and_bounds_fail_closed() {
        let mut adapter = adapter(10, 1_000);
        let first = adapter
            .build_request(10, &generated(CommandKind::NewOrder, 1))
            .unwrap();
        let second = adapter
            .build_request(11, &generated(CommandKind::NewOrder, 2))
            .unwrap();
        adapter.apply_response(accepted(&second, Some(2))).unwrap();
        adapter.apply_response(accepted(&first, Some(1))).unwrap();
        assert_eq!(adapter.live_order_count(), 2);

        for request_id in 20..24 {
            adapter
                .build_request(request_id, &generated(CommandKind::NewOrder, 1))
                .unwrap();
        }
        assert_eq!(
            adapter.build_request(24, &generated(CommandKind::NewOrder, 1)),
            Err(RpcAdapterError::InFlightFull)
        );
    }

    #[test]
    fn bounded_live_order_sample_rolls_over_without_ending_long_runs() {
        let mut adapter = RpcSessionAdapter::new(RpcSessionConfig {
            account: AccountId::new(7),
            client_id: 10,
            nonce_base: 1_000,
            signing_seed: [3; 32],
            max_in_flight: 1,
            max_live_orders: 2,
        })
        .unwrap();
        for index in 0..10 {
            let request = adapter
                .build_request(index, &generated(CommandKind::NewOrder, 1))
                .unwrap();
            adapter
                .apply_response(accepted(&request, Some(100 + index)))
                .unwrap();
        }
        assert_eq!(adapter.live_order_count(), 2);
        let cancel = adapter
            .build_request(11, &generated(CommandKind::Cancel, 1))
            .unwrap();
        assert!(matches!(cancel.method, RpcMethod::CancelOrder(..)));
    }

    #[test]
    fn distributed_partitions_never_reuse_client_nonce_pairs() {
        let mut left = adapter(100, 1u64 << 32);
        let mut right = adapter(101, 2u64 << 32);
        let left_request = left
            .build_request(1, &generated(CommandKind::NewOrder, 1))
            .unwrap();
        let right_request = right
            .build_request(1, &generated(CommandKind::NewOrder, 1))
            .unwrap();
        let left_meta = left_request.method.control_meta().unwrap();
        let right_meta = right_request.method.control_meta().unwrap();
        assert_ne!(
            (left_meta.client_id, left_meta.nonce),
            (right_meta.client_id, right_meta.nonce)
        );
    }
}
