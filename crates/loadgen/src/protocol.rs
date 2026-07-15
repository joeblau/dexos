//! Production DexOS signed RPC adapter for generated trading operations.

use crypto::KeyPair;
use proto::{
    decode_response, encode_request, encode_request_into, CancelOrderParams, Command, CommandAck,
    ControlMeta, ReplaceOrderParams, RpcError, RpcMethod, RpcOk, RpcRequest, RpcResponse,
    SubmitOrderParams,
};
use types::{AccountId, Ratio, RATIO_SCALE};

use crate::command::{CommandKind, GeneratedCommand, SessionState};

/// Encoded real production request plus correlation metadata retained by a bounded
/// in-flight table.
#[derive(Debug, Clone)]
pub struct EncodedOperation {
    pub request_id: u64,
    pub client_id: u64,
    pub nonce: u64,
    pub command: GeneratedCommand,
    pub bytes: Vec<u8>,
}

/// Reusable caller-owned storage for signing, serialization, and framing.
#[derive(Debug)]
pub struct ProtocolSlot {
    signing_scratch: Box<[u8]>,
    payload_scratch: Box<[u8]>,
    frame: Vec<u8>,
}

impl ProtocolSlot {
    #[must_use]
    pub fn new(signing_capacity: usize, payload_capacity: usize, frame_capacity: usize) -> Self {
        Self {
            signing_scratch: vec![0; signing_capacity].into_boxed_slice(),
            payload_scratch: vec![0; payload_capacity].into_boxed_slice(),
            frame: Vec::with_capacity(frame_capacity),
        }
    }

    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    #[must_use]
    pub fn frame_capacity(&self) -> usize {
        self.frame.capacity()
    }
}

/// Correlation metadata returned by in-place encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedMetadata {
    pub request_id: u64,
    pub client_id: u64,
    pub nonce: u64,
    pub frame_len: usize,
}

/// Successful or rejected correlated production response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOutcome {
    Accepted(CommandAck),
    Rejected(RpcError),
}

/// Typed adapter failure; these map to generator or protocol-failed counters, never
/// transport rejection.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolAdapterError {
    #[error("identity namespace overflow for session {session}")]
    IdentityOverflow { session: u32 },
    #[error("{kind:?} command is missing an accepted target order")]
    MissingTarget { kind: CommandKind },
    #[error("production RPC encode/decode failed: {0}")]
    Rpc(#[from] RpcError),
    #[error("response correlation mismatch: expected request {expected}, got {actual}")]
    Correlation { expected: u64, actual: u64 },
    #[error("accepted acknowledgement is inconsistent with the generated command: {0}")]
    InvalidAcknowledgement(String),
}

/// A signer/account and disjoint client-ID namespace assigned to one agent partition.
#[derive(Debug, Clone)]
pub struct ProtocolAdapter {
    account: AccountId,
    signer: KeyPair,
    client_id_base: u64,
    session_pubkey: Option<[u8; 32]>,
}

impl ProtocolAdapter {
    #[must_use]
    pub fn new(
        account: AccountId,
        signer: KeyPair,
        client_id_base: u64,
        session_pubkey: Option<[u8; 32]>,
    ) -> Self {
        Self {
            account,
            signer,
            client_id_base,
            session_pubkey,
        }
    }

    /// Apply a controller-assigned disjoint client namespace without exposing or
    /// retransmitting agent-local signing material.
    #[must_use]
    pub fn with_client_id_base(mut self, client_id_base: u64) -> Self {
        self.client_id_base = client_id_base;
        self
    }

    /// Sign and frame one of the three real trading RPC methods.
    pub fn encode(
        &self,
        request_id: u64,
        command: GeneratedCommand,
    ) -> Result<EncodedOperation, ProtocolAdapterError> {
        let client_id = self
            .client_id_base
            .checked_add(u64::from(command.session))
            .ok_or(ProtocolAdapterError::IdentityOverflow {
                session: command.session,
            })?;
        let mut scratch = None;
        let method = self.method_for(client_id, &command, &mut scratch)?;
        let request = RpcRequest::new(request_id, method);
        let bytes = encode_request(&request)?;
        Ok(EncodedOperation {
            request_id,
            client_id,
            nonce: command.nonce,
            command,
            bytes,
        })
    }

    /// Sign, serialize, and frame into startup-allocated storage. Buffers are never
    /// resized; undersized storage returns a typed error.
    pub fn encode_into_slot(
        &self,
        request_id: u64,
        command: &GeneratedCommand,
        slot: &mut ProtocolSlot,
    ) -> Result<EncodedMetadata, ProtocolAdapterError> {
        let client_id = self
            .client_id_base
            .checked_add(u64::from(command.session))
            .ok_or(ProtocolAdapterError::IdentityOverflow {
                session: command.session,
            })?;
        let mut scratch = Some(slot.signing_scratch.as_mut());
        let method = self.method_for(client_id, command, &mut scratch)?;
        let request = RpcRequest::new(request_id, method);
        let frame_len =
            encode_request_into(&request, slot.payload_scratch.as_mut(), &mut slot.frame)?;
        Ok(EncodedMetadata {
            request_id,
            client_id,
            nonce: command.nonce,
            frame_len,
        })
    }

    fn method_for(
        &self,
        client_id: u64,
        command: &GeneratedCommand,
        scratch: &mut Option<&mut [u8]>,
    ) -> Result<RpcMethod, ProtocolAdapterError> {
        match command.kind {
            CommandKind::NewOrder => {
                let params = SubmitOrderParams {
                    account: self.account,
                    market: command.market,
                    side: command.side,
                    order_type: command.order_type,
                    price: command.price,
                    quantity: command.quantity,
                    time_in_force: command.time_in_force,
                    leverage: Ratio::from_raw(RATIO_SCALE),
                };
                let lowered = params.to_command();
                let meta = self.sign_meta(client_id, command.nonce, &lowered, scratch)?;
                Ok(RpcMethod::SubmitOrder(meta, params))
            }
            CommandKind::Cancel => {
                let order_id = command
                    .target_order
                    .ok_or(ProtocolAdapterError::MissingTarget {
                        kind: CommandKind::Cancel,
                    })?;
                let params = CancelOrderParams {
                    account: self.account,
                    market: command.market,
                    order_id,
                };
                let lowered = params.to_command();
                let meta = self.sign_meta(client_id, command.nonce, &lowered, scratch)?;
                Ok(RpcMethod::CancelOrder(meta, params))
            }
            CommandKind::Replace => {
                let order_id = command
                    .target_order
                    .ok_or(ProtocolAdapterError::MissingTarget {
                        kind: CommandKind::Replace,
                    })?;
                let params = ReplaceOrderParams {
                    account: self.account,
                    market: command.market,
                    order_id,
                    new_price: command.price,
                    new_quantity: command.quantity,
                };
                let lowered = params.to_command();
                let meta = self.sign_meta(client_id, command.nonce, &lowered, scratch)?;
                Ok(RpcMethod::ReplaceOrder(meta, params))
            }
        }
    }

    fn sign_meta(
        &self,
        client_id: u64,
        nonce: u64,
        command: &Command,
        scratch: &mut Option<&mut [u8]>,
    ) -> Result<ControlMeta, RpcError> {
        match scratch.as_deref_mut() {
            Some(buffer) => ControlMeta::signed_with_scratch(
                client_id,
                nonce,
                self.session_pubkey,
                &self.signer,
                command,
                buffer,
            ),
            None => {
                ControlMeta::signed(client_id, nonce, self.session_pubkey, &self.signer, command)
            }
        }
    }

    /// Decode and correlate a response without assuming acknowledgement order.
    pub fn decode_response(
        &self,
        expected_request_id: u64,
        bytes: &[u8],
    ) -> Result<ProtocolOutcome, ProtocolAdapterError> {
        let response = decode_response(bytes)?;
        self.correlate_response(expected_request_id, response)
    }

    pub fn correlate_response(
        &self,
        expected_request_id: u64,
        response: RpcResponse,
    ) -> Result<ProtocolOutcome, ProtocolAdapterError> {
        if response.request_id != expected_request_id {
            return Err(ProtocolAdapterError::Correlation {
                expected: expected_request_id,
                actual: response.request_id,
            });
        }
        match response.result {
            Ok(RpcOk::CommandAck(ack)) => Ok(ProtocolOutcome::Accepted(ack)),
            Ok(other) => Err(ProtocolAdapterError::InvalidAcknowledgement(format!(
                "expected CommandAck, got {other:?}"
            ))),
            Err(error) => Ok(ProtocolOutcome::Rejected(error)),
        }
    }

    /// Apply accepted acknowledgement state to the owning session. Market/order IDs
    /// must agree with the request; stale/wrong-market acknowledgements fail closed.
    pub fn apply_accepted(
        &self,
        session: &mut SessionState,
        operation: &EncodedOperation,
        acknowledgement: &CommandAck,
    ) -> Result<(), ProtocolAdapterError> {
        self.apply_accepted_command(session, &operation.command, acknowledgement)
    }

    /// Apply an accepted acknowledgement when the runtime stores command and frame
    /// slots separately to avoid constructing an owned [`EncodedOperation`].
    pub fn apply_accepted_command(
        &self,
        session: &mut SessionState,
        command: &GeneratedCommand,
        acknowledgement: &CommandAck,
    ) -> Result<(), ProtocolAdapterError> {
        if acknowledgement.market_id != Some(command.market) {
            return Err(ProtocolAdapterError::InvalidAcknowledgement(
                "acknowledged market does not match request".to_string(),
            ));
        }
        let updated = match command.kind {
            CommandKind::NewOrder => acknowledgement
                .order_id
                .is_some_and(|order_id| session.accept_new_order(order_id, command)),
            CommandKind::Cancel => command.target_order.is_some_and(|order_id| {
                acknowledgement.order_id == Some(order_id)
                    && session.accept_cancel(order_id, command.market)
            }),
            CommandKind::Replace => command.target_order.is_some_and(|order_id| {
                acknowledgement.order_id == Some(order_id) && session.accept_replace(command)
            }),
        };
        session.release_pending(command);
        if !updated {
            return Err(ProtocolAdapterError::InvalidAcknowledgement(
                "acknowledged order is missing, stale, full, or not owned by this session"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{decode_request, encode_response, FinalityStatus};
    use types::{Hash, OrderId};

    use crate::campaign::OperationMix;
    use crate::{Lcg, LoadScenario};

    fn adapter() -> ProtocolAdapter {
        ProtocolAdapter::new(
            AccountId::new(42),
            KeyPair::from_seed(&[9u8; 32]),
            10_000,
            None,
        )
    }

    fn scenario() -> LoadScenario {
        LoadScenario {
            market_ids: vec![7],
            operation_mix: Some(OperationMix {
                new: Ratio::from_raw(RATIO_SCALE),
                cancel: Ratio::ZERO,
                replace: Ratio::ZERO,
            }),
            ..LoadScenario::default()
        }
    }

    #[test]
    fn real_submit_request_is_signed_and_round_trips() {
        let scenario = scenario();
        let mut session = SessionState::with_partition(3, &scenario, "agent", 0, false);
        let command = session.next_command(&mut Lcg::new(0), &scenario);
        let encoded = adapter().encode(77, command).unwrap();
        let request = decode_request(&encoded.bytes).unwrap();
        assert_eq!(request.request_id, 77);
        match request.method {
            RpcMethod::SubmitOrder(meta, params) => {
                assert_eq!(meta.client_id, 10_003);
                assert_eq!(meta.nonce, command.nonce);
                assert_eq!(params.market, command.market);
                meta.verify_signature(&params.to_command()).unwrap();
            }
            other => panic!("expected real SubmitOrder, got {other:?}"),
        }
    }

    #[test]
    fn correlated_ack_drives_live_order_state() {
        let scenario = scenario();
        let mut session = SessionState::with_partition(3, &scenario, "agent", 0, false);
        let command = session.next_command(&mut Lcg::new(0), &scenario);
        let adapter = adapter();
        let operation = adapter.encode(88, command).unwrap();
        let ack = CommandAck {
            command_hash: Hash::ZERO,
            finality: FinalityStatus::Accepted,
            order_id: Some(OrderId::new(123)),
            market_id: Some(command.market),
        };
        let bytes =
            encode_response(&RpcResponse::new(88, Ok(RpcOk::CommandAck(ack.clone())))).unwrap();
        let outcome = adapter.decode_response(88, &bytes).unwrap();
        assert_eq!(outcome, ProtocolOutcome::Accepted(ack.clone()));
        adapter
            .apply_accepted(&mut session, &operation, &ack)
            .unwrap();
        assert_eq!(session.live_orders()[0].order_id, OrderId::new(123));
    }

    #[test]
    fn partitions_and_correlation_cannot_alias() {
        let first = ProtocolAdapter::new(AccountId::new(1), KeyPair::from_seed(&[1; 32]), 0, None);
        let second = ProtocolAdapter::new(
            AccountId::new(1),
            KeyPair::from_seed(&[1; 32]),
            1_000_000,
            None,
        );
        let scenario = scenario();
        let mut session = SessionState::with_partition(1, &scenario, "agent", 0, false);
        let command = session.next_command(&mut Lcg::new(0), &scenario);
        let a = first.encode(1, command).unwrap();
        let b = second.encode(1, command).unwrap();
        assert_ne!((a.client_id, a.nonce), (b.client_id, b.nonce));

        let response = RpcResponse::new(2, Err(RpcError::Backpressure));
        assert!(matches!(
            first.correlate_response(1, response),
            Err(ProtocolAdapterError::Correlation { .. })
        ));
    }

    #[test]
    fn in_place_protocol_encoding_reuses_fixed_capacity() {
        let scenario = scenario();
        let mut session = SessionState::with_partition(3, &scenario, "agent", 0, false);
        let mut ignored = Lcg::new(0);
        let adapter = adapter();
        let mut slot = ProtocolSlot::new(2048, 2048, 4096);
        let capacity = slot.frame_capacity();
        for request_id in 1..=10_000 {
            let command = session.next_command(&mut ignored, &scenario);
            let metadata = adapter
                .encode_into_slot(request_id, &command, &mut slot)
                .unwrap();
            assert_eq!(metadata.request_id, request_id);
            assert_eq!(metadata.frame_len, slot.frame().len());
            assert_eq!(slot.frame_capacity(), capacity);
            let decoded = decode_request(slot.frame()).unwrap();
            assert_eq!(decoded.request_id, request_id);
        }
    }

    #[test]
    fn undersized_protocol_slot_is_a_typed_failure() {
        let scenario = scenario();
        let mut session = SessionState::with_partition(3, &scenario, "agent", 0, false);
        let command = session.next_command(&mut Lcg::new(0), &scenario);
        let mut slot = ProtocolSlot::new(1, 1, 1);
        assert!(matches!(
            adapter().encode_into_slot(1, &command, &mut slot),
            Err(ProtocolAdapterError::Rpc(_))
        ));
        assert_eq!(slot.frame_capacity(), 1);
    }
}
