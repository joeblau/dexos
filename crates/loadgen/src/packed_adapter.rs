//! Auth-amortized production packed-batch adapter for measured load.
//!
//! One adapter owns a single established session. It converts deterministic
//! workload actions into canonical [`codec::PackedOrder`] records, signs one
//! [`network::AuthenticatedOrderBatchCodec`] wrapper for 32-128 records, and
//! retains bounded pending effects until the target acknowledges admission.

use codec::{encode_batch_into, PackedOrder, PackedOrderError, PACKED_SUBMIT_LEN};
use crypto::KeyPair;
use network::{
    AuthenticatedOrderBatchCodec, AuthenticatedOrderBatchError, OrderBatchBinding,
    OrderBatchReceipt, OrderBatchReceiptStage,
};
use types::{AccountId, MarketId, OrderId, Ratio, TimeInForce, RATIO_SCALE};

use crate::{CommandKind, GeneratedCommand};

const MIN_BATCH_RECORDS: usize = 32;
const MAX_BATCH_RECORDS: usize = 128;
const MAX_PACKED_BYTES: usize = MAX_BATCH_RECORDS * PACKED_SUBMIT_LEN;

/// Fixed identity, sequence namespace, and memory bounds for one packed session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedSessionConfig {
    /// Destination identity signed into every batch.
    pub destination: [u8; 32],
    /// Session reference established by the target handshake.
    pub session_ref: u32,
    /// Funded account authorized by the session key.
    pub account: AccountId,
    /// Stable client idempotency namespace.
    pub client_id: u64,
    /// First command nonce in this controller-assigned namespace.
    pub nonce_base: u64,
    /// External session signing seed. It is never included in reports.
    pub signing_seed: [u8; 32],
    /// First strict per-session batch sequence.
    pub first_batch_sequence: u64,
    /// First canonical sequencer number expected from the target.
    pub first_command_sequence: u64,
    /// Server-issued per-session batch-sequence advance.
    pub batch_sequence_stride: u64,
    /// Server-issued per-session command-sequence advance. Zero selects the
    /// contiguous single-session default (the admitted record count).
    pub command_sequence_stride: u64,
    /// Maximum batches awaiting admission receipts.
    pub max_in_flight_batches: usize,
    /// Maximum admitted live orders sampled for cancel/replace traffic.
    pub max_live_orders: usize,
}

/// Owned wire payload retained by a caller for exact retry until admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPackedBatch {
    pub batch_sequence: u64,
    pub first_sequence: u64,
    pub record_count: u8,
    pub bytes: Vec<u8>,
}

/// Correlated successful admission applied to local lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedBatchOutcome {
    pub batch_sequence: u64,
    pub record_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LiveOrder {
    id: OrderId,
    market: MarketId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingEffect {
    None,
    Add(LiveOrder),
    Remove(LiveOrder),
    Replace(LiveOrder),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingBatch {
    batch_sequence: u64,
    first_sequence: u64,
    record_count: u8,
    effects: [PendingEffect; MAX_BATCH_RECORDS],
}

/// Bounded stateful adapter for an established authenticated packed session.
pub struct PackedSessionAdapter {
    config: PackedSessionConfig,
    signer: KeyPair,
    codec: AuthenticatedOrderBatchCodec,
    next_nonce: u64,
    next_batch_sequence: u64,
    next_command_sequence: u64,
    batch_sequence_stride: u64,
    command_sequence_stride: u64,
    live_orders: Vec<LiveOrder>,
    next_live_replacement: usize,
    pending: Vec<PendingBatch>,
    records: [PackedOrder; MAX_BATCH_RECORDS],
    record_bytes: [u8; MAX_PACKED_BYTES],
}

impl PackedSessionAdapter {
    /// Allocate all bounded session state once.
    pub fn new(config: PackedSessionConfig) -> Result<Self, PackedAdapterError> {
        Self::new_striped(
            config,
            config.batch_sequence_stride,
            config.command_sequence_stride,
        )
    }

    /// Allocate a server-issued striped sequence lease. A zero command stride
    /// retains contiguous single-session advancement by the batch record count.
    pub fn new_striped(
        config: PackedSessionConfig,
        batch_sequence_stride: u64,
        command_sequence_stride: u64,
    ) -> Result<Self, PackedAdapterError> {
        if config.max_in_flight_batches == 0 || config.max_live_orders == 0 {
            return Err(PackedAdapterError::InvalidConfig);
        }
        if batch_sequence_stride == 0 {
            return Err(PackedAdapterError::InvalidConfig);
        }
        let placeholder = PackedOrder::Cancel {
            session_ref: config.session_ref,
            nonce: config.nonce_base,
            client_id: config.client_id,
            account: config.account,
            market: MarketId::new(0),
            order_id: OrderId::new(0),
        };
        Ok(Self {
            config,
            signer: KeyPair::from_seed(&config.signing_seed),
            codec: AuthenticatedOrderBatchCodec::new(),
            next_nonce: config.nonce_base,
            next_batch_sequence: config.first_batch_sequence,
            next_command_sequence: config.first_command_sequence,
            batch_sequence_stride,
            command_sequence_stride,
            live_orders: Vec::with_capacity(config.max_live_orders),
            next_live_replacement: 0,
            pending: Vec::with_capacity(config.max_in_flight_batches),
            records: [placeholder; MAX_BATCH_RECORDS],
            record_bytes: [0; MAX_PACKED_BYTES],
        })
    }

    /// Session public key expected by the target's established session binding.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public()
    }

    #[must_use]
    pub const fn next_batch_sequence(&self) -> u64 {
        self.next_batch_sequence
    }

    #[must_use]
    pub const fn next_command_sequence(&self) -> u64 {
        self.next_command_sequence
    }

    #[must_use]
    pub fn in_flight_batches(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn live_order_count(&self) -> usize {
        self.live_orders.len()
    }

    /// Prepare one exact signed payload. The owned bytes must be retained for an
    /// identical retry until [`Self::acknowledge_admission`] succeeds.
    pub fn prepare_batch(
        &mut self,
        generated: &[GeneratedCommand],
    ) -> Result<PreparedPackedBatch, PackedAdapterError> {
        if !(MIN_BATCH_RECORDS..=MAX_BATCH_RECORDS).contains(&generated.len()) {
            return Err(PackedAdapterError::BatchSizeOutOfRange(generated.len()));
        }
        if self.pending.len() >= self.config.max_in_flight_batches {
            return Err(PackedAdapterError::InFlightFull);
        }
        let count =
            u64::try_from(generated.len()).map_err(|_| PackedAdapterError::SequenceExhausted)?;
        let next_nonce = self
            .next_nonce
            .checked_add(count)
            .ok_or(PackedAdapterError::NonceExhausted)?;
        let next_batch_sequence = self
            .next_batch_sequence
            .checked_add(self.batch_sequence_stride)
            .ok_or(PackedAdapterError::SequenceExhausted)?;
        if self.command_sequence_stride != 0 && self.command_sequence_stride < count {
            return Err(PackedAdapterError::InvalidConfig);
        }
        let command_advance = if self.command_sequence_stride == 0 {
            count
        } else {
            self.command_sequence_stride
        };
        let next_command_sequence = self
            .next_command_sequence
            .checked_add(command_advance)
            .ok_or(PackedAdapterError::SequenceExhausted)?;

        let mut effects = [PendingEffect::None; MAX_BATCH_RECORDS];
        for (index, command) in generated.iter().enumerate() {
            let nonce = self.next_nonce + u64::try_from(index).unwrap_or(u64::MAX);
            let (record, effect) = self.record_for(command, nonce, &effects[..index]);
            self.records[index] = record;
            effects[index] = effect;
        }
        let record_len =
            encode_batch_into(&self.records[..generated.len()], &mut self.record_bytes)?;
        let record_count = u8::try_from(generated.len())
            .map_err(|_| PackedAdapterError::BatchSizeOutOfRange(generated.len()))?;
        let binding = OrderBatchBinding {
            destination: self.config.destination,
            session_ref: self.config.session_ref,
            account: self.config.account,
            batch_sequence: self.next_batch_sequence,
            first_sequence: self.next_command_sequence,
        };
        let encoded = self.codec.encode(
            binding,
            &self.signer,
            record_count,
            false,
            &self.record_bytes[..record_len],
        )?;
        let prepared = PreparedPackedBatch {
            batch_sequence: binding.batch_sequence,
            first_sequence: binding.first_sequence,
            record_count,
            bytes: encoded.bytes.to_vec(),
        };
        self.pending.push(PendingBatch {
            batch_sequence: binding.batch_sequence,
            first_sequence: binding.first_sequence,
            record_count,
            effects,
        });
        self.next_nonce = next_nonce;
        self.next_batch_sequence = next_batch_sequence;
        self.next_command_sequence = next_command_sequence;
        Ok(prepared)
    }

    /// Apply a correlated successful admission exactly once. Rejections and
    /// transport backpressure must retain the prepared bytes and retry them.
    pub fn acknowledge_admission(
        &mut self,
        batch_sequence: u64,
    ) -> Result<PackedBatchOutcome, PackedAdapterError> {
        let position = self
            .pending
            .iter()
            .position(|batch| batch.batch_sequence == batch_sequence)
            .ok_or(PackedAdapterError::UnknownAdmission(batch_sequence))?;
        let pending = self.pending.swap_remove(position);

        // Remove first so a bounded-table insertion from the same admitted batch
        // cannot evict an order that a later effect still needs to remove.
        for effect in pending.effects[..usize::from(pending.record_count)].iter() {
            if let PendingEffect::Remove(order) = effect {
                self.remove_live(*order)?;
            }
        }
        for effect in pending.effects[..usize::from(pending.record_count)].iter() {
            match effect {
                PendingEffect::Add(order) => self.add_live(*order),
                PendingEffect::Replace(order) => {
                    if !self.live_orders.contains(order) {
                        return Err(PackedAdapterError::StaleAdmission);
                    }
                }
                PendingEffect::None | PendingEffect::Remove(_) => {}
            }
        }
        Ok(PackedBatchOutcome {
            batch_sequence,
            record_count: pending.record_count,
        })
    }

    /// Correlate the first authenticated-transport receipt for a pending batch.
    /// Executed/finalized receipts also prove full admission, while a rejection
    /// leaves local lifecycle state unchanged and invalidates the measured run.
    pub fn acknowledge_receipt(
        &mut self,
        receipt: &OrderBatchReceipt,
    ) -> Result<PackedBatchOutcome, PackedAdapterError> {
        let pending = self
            .pending
            .iter()
            .find(|batch| batch.batch_sequence == receipt.batch_sequence)
            .ok_or(PackedAdapterError::UnknownAdmission(receipt.batch_sequence))?;
        if pending.first_sequence != receipt.first_sequence
            || pending.record_count != receipt.record_count
        {
            return Err(PackedAdapterError::ReceiptMismatch);
        }
        if receipt.stage == OrderBatchReceiptStage::Rejected {
            return Err(PackedAdapterError::TargetRejected(receipt.rejection_code));
        }
        if receipt.admitted != receipt.record_count {
            return Err(PackedAdapterError::ReceiptMismatch);
        }
        self.acknowledge_admission(receipt.batch_sequence)
    }

    fn record_for(
        &self,
        generated: &GeneratedCommand,
        nonce: u64,
        current_effects: &[PendingEffect],
    ) -> (PackedOrder, PendingEffect) {
        let selected = self.select_live(generated, current_effects);
        match (generated.kind, selected) {
            (CommandKind::Cancel, Some(order)) => (
                PackedOrder::Cancel {
                    session_ref: self.config.session_ref,
                    nonce,
                    client_id: self.config.client_id,
                    account: self.config.account,
                    market: order.market,
                    order_id: order.id,
                },
                PendingEffect::Remove(order),
            ),
            (CommandKind::Replace, Some(order)) => (
                PackedOrder::Replace {
                    session_ref: self.config.session_ref,
                    nonce,
                    client_id: self.config.client_id,
                    account: self.config.account,
                    market: order.market,
                    order_id: order.id,
                    new_price: generated.price,
                    new_quantity: generated.quantity,
                },
                PendingEffect::Replace(order),
            ),
            _ => {
                let order = LiveOrder {
                    id: OrderId::new(nonce),
                    market: generated.market,
                };
                (
                    PackedOrder::Submit {
                        session_ref: self.config.session_ref,
                        nonce,
                        client_id: self.config.client_id,
                        account: self.config.account,
                        market: generated.market,
                        side: generated.side,
                        order_type: generated.order_type,
                        price: generated.price,
                        quantity: generated.quantity,
                        time_in_force: TimeInForce::Gtc,
                        leverage: Ratio::from_raw(RATIO_SCALE),
                    },
                    PendingEffect::Add(order),
                )
            }
        }
    }

    fn select_live(
        &self,
        generated: &GeneratedCommand,
        current_effects: &[PendingEffect],
    ) -> Option<LiveOrder> {
        generated
            .target_order
            .and_then(|id| {
                self.live_orders.iter().copied().find(|order| {
                    order.id == id && !self.order_is_reserved(*order, current_effects)
                })
            })
            .or_else(|| {
                self.live_orders
                    .iter()
                    .copied()
                    .find(|order| !self.order_is_reserved(*order, current_effects))
            })
    }

    fn order_is_reserved(&self, order: LiveOrder, current_effects: &[PendingEffect]) -> bool {
        self.pending
            .iter()
            .flat_map(|batch| batch.effects[..usize::from(batch.record_count)].iter())
            .chain(current_effects)
            .any(|effect| {
                matches!(
                    effect,
                    PendingEffect::Remove(reserved) | PendingEffect::Replace(reserved)
                        if *reserved == order
                )
            })
    }

    fn add_live(&mut self, order: LiveOrder) {
        if self.live_orders.len() < self.config.max_live_orders {
            self.live_orders.push(order);
        } else {
            let index = self.next_live_replacement % self.live_orders.len();
            self.live_orders[index] = order;
            self.next_live_replacement = (index + 1) % self.live_orders.len();
        }
    }

    fn remove_live(&mut self, order: LiveOrder) -> Result<(), PackedAdapterError> {
        let position = self
            .live_orders
            .iter()
            .position(|candidate| *candidate == order)
            .ok_or(PackedAdapterError::StaleAdmission)?;
        self.live_orders.swap_remove(position);
        Ok(())
    }
}

/// Packed session construction, encoding, or receipt-correlation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackedAdapterError {
    #[error("invalid packed session capacity")]
    InvalidConfig,
    #[error("packed batch record count {0} is outside 32..=128")]
    BatchSizeOutOfRange(usize),
    #[error("packed batch in-flight table is full")]
    InFlightFull,
    #[error("packed command nonce space is exhausted")]
    NonceExhausted,
    #[error("packed batch or command sequence is exhausted")]
    SequenceExhausted,
    #[error("unknown packed admission sequence {0}")]
    UnknownAdmission(u64),
    #[error("packed admission lifecycle state is stale")]
    StaleAdmission,
    #[error("packed receipt does not match the prepared sequence range or record count")]
    ReceiptMismatch,
    #[error("target rejected the complete packed batch with code {0}")]
    TargetRejected(u16),
    #[error("packed record encoding failed: {0}")]
    Record(#[from] PackedOrderError),
    #[error("authenticated packed batch encoding failed: {0}")]
    Authentication(#[from] AuthenticatedOrderBatchError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use network::{OrderBatchCodec, OrderBatchReplayGuard};
    use types::{OrderType, Price, Quantity, Side};

    fn config() -> PackedSessionConfig {
        PackedSessionConfig {
            destination: [9; 32],
            session_ref: 7,
            account: AccountId::new(3),
            client_id: 44,
            nonce_base: 1_000,
            signing_seed: [5; 32],
            first_batch_sequence: 20,
            first_command_sequence: 30_000,
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
            max_in_flight_batches: 4,
            max_live_orders: 64,
        }
    }

    fn commands(kind: CommandKind) -> Vec<GeneratedCommand> {
        (0..32)
            .map(|index| GeneratedCommand {
                session: 1,
                nonce: index,
                idempotency_key: u128::from(index),
                market: MarketId::new(u32::try_from(index % 2).unwrap_or(0)),
                kind,
                side: if index % 2 == 0 { Side::Bid } else { Side::Ask },
                order_type: OrderType::Limit,
                price: Price::from_raw(10_000 + i64::try_from(index).unwrap_or(0)),
                quantity: Quantity::from_raw(1_000),
                target_order: None,
            })
            .collect()
    }

    #[test]
    fn prepared_batch_is_exactly_signed_bound_and_sequence_contiguous() {
        let config = config();
        let mut adapter = PackedSessionAdapter::new(config).unwrap();
        let prepared = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();

        assert_eq!(prepared.batch_sequence, 20);
        assert_eq!(prepared.first_sequence, 30_000);
        assert_eq!(prepared.record_count, 32);
        let verified =
            AuthenticatedOrderBatchCodec::verify(&prepared.bytes, &config.destination).unwrap();
        assert_eq!(verified.signer, adapter.public_key());
        assert_eq!(verified.binding.session_ref, config.session_ref);
        assert_eq!(verified.binding.account, config.account);
        assert_eq!(
            OrderBatchCodec::inspect_record_count(verified.envelope),
            Ok(32)
        );

        let mut replay = OrderBatchReplayGuard::new(20, 30_000);
        replay.check_admission(&verified.binding, 32).unwrap();
        replay.commit(&verified.binding, 32).unwrap();
        assert_eq!(replay.next_batch_sequence(), 21);
        assert_eq!(replay.next_first_sequence(), 30_032);
        assert_eq!(adapter.next_batch_sequence(), 21);
        assert_eq!(adapter.next_command_sequence(), 30_032);
    }

    #[test]
    fn striped_adapter_advances_by_server_issued_global_lanes() {
        let config = config();
        let mut adapter = PackedSessionAdapter::new_striped(config, 3, 96).unwrap();
        let first = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();
        assert_eq!(first.batch_sequence, 20);
        assert_eq!(first.first_sequence, 30_000);
        assert_eq!(adapter.next_batch_sequence(), 23);
        assert_eq!(adapter.next_command_sequence(), 30_096);
        let second = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();
        assert_eq!(second.batch_sequence, 23);
        assert_eq!(second.first_sequence, 30_096);

        assert!(matches!(
            PackedSessionAdapter::new_striped(config, 3, 31)
                .unwrap()
                .prepare_batch(&commands(CommandKind::NewOrder)),
            Err(PackedAdapterError::InvalidConfig)
        ));
    }

    #[test]
    fn lifecycle_changes_only_after_correlated_admission() {
        let mut adapter = PackedSessionAdapter::new(config()).unwrap();
        let first = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();
        assert_eq!(adapter.live_order_count(), 0);
        assert_eq!(adapter.in_flight_batches(), 1);
        let receipt = OrderBatchReceipt {
            stage: OrderBatchReceiptStage::Admitted,
            record_count: first.record_count,
            admitted: first.record_count,
            executed: 0,
            finalized: 0,
            failed: 0,
            rejection_code: 0,
            batch_sequence: first.batch_sequence,
            first_sequence: first.first_sequence,
            checkpoint_height: None,
            observed_unix_ns: 1,
        };
        assert_eq!(
            adapter.acknowledge_receipt(&receipt).unwrap().record_count,
            32
        );
        assert_eq!(adapter.live_order_count(), 32);

        let cancels = adapter
            .prepare_batch(&commands(CommandKind::Cancel))
            .unwrap();
        assert_eq!(adapter.live_order_count(), 32);
        adapter
            .acknowledge_admission(cancels.batch_sequence)
            .unwrap();
        assert_eq!(adapter.live_order_count(), 0);
        assert_eq!(
            adapter.acknowledge_admission(cancels.batch_sequence),
            Err(PackedAdapterError::UnknownAdmission(cancels.batch_sequence))
        );
    }

    #[test]
    fn mismatched_or_rejected_receipt_never_commits_lifecycle_state() {
        let mut adapter = PackedSessionAdapter::new(config()).unwrap();
        let batch = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();
        let mut receipt = OrderBatchReceipt {
            stage: OrderBatchReceiptStage::Admitted,
            record_count: batch.record_count,
            admitted: batch.record_count,
            executed: 0,
            finalized: 0,
            failed: 0,
            rejection_code: 0,
            batch_sequence: batch.batch_sequence,
            first_sequence: batch.first_sequence + 1,
            checkpoint_height: None,
            observed_unix_ns: 1,
        };
        assert_eq!(
            adapter.acknowledge_receipt(&receipt),
            Err(PackedAdapterError::ReceiptMismatch)
        );
        receipt.stage = OrderBatchReceiptStage::Rejected;
        receipt.admitted = 0;
        receipt.rejection_code = 9;
        receipt.first_sequence = batch.first_sequence;
        assert_eq!(
            adapter.acknowledge_receipt(&receipt),
            Err(PackedAdapterError::TargetRejected(9))
        );
        assert_eq!(adapter.live_order_count(), 0);
        assert_eq!(adapter.in_flight_batches(), 1);
    }

    #[test]
    fn in_flight_lifecycle_reservations_prevent_duplicate_cancel() {
        let mut adapter = PackedSessionAdapter::new(config()).unwrap();
        let submitted = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();
        adapter
            .acknowledge_admission(submitted.batch_sequence)
            .unwrap();

        let first = adapter
            .prepare_batch(&commands(CommandKind::Cancel))
            .unwrap();
        let second = adapter
            .prepare_batch(&commands(CommandKind::Cancel))
            .unwrap();
        let verified = AuthenticatedOrderBatchCodec::verify(&second.bytes, &[9; 32]).unwrap();
        let mut scratch = vec![0; network::ORDER_BATCH_MAX_UNCOMPRESSED];
        let mut records = [adapter.records[0]; MAX_BATCH_RECORDS];
        let decoded =
            OrderBatchCodec::decode_records_into(verified.envelope, &mut scratch, &mut records)
                .unwrap();
        assert!(decoded
            .records
            .iter()
            .all(|record| matches!(record, PackedOrder::Submit { .. })));

        adapter.acknowledge_admission(first.batch_sequence).unwrap();
        adapter
            .acknowledge_admission(second.batch_sequence)
            .unwrap();
        assert_eq!(adapter.live_order_count(), 32);
    }

    #[test]
    fn invalid_sizes_and_capacity_fail_closed() {
        let mut config = config();
        config.max_in_flight_batches = 1;
        let mut adapter = PackedSessionAdapter::new(config).unwrap();
        assert_eq!(
            adapter.prepare_batch(&commands(CommandKind::NewOrder)[..31]),
            Err(PackedAdapterError::BatchSizeOutOfRange(31))
        );
        let _ = adapter
            .prepare_batch(&commands(CommandKind::NewOrder))
            .unwrap();
        assert_eq!(
            adapter.prepare_batch(&commands(CommandKind::NewOrder)),
            Err(PackedAdapterError::InFlightFull)
        );
    }
}
