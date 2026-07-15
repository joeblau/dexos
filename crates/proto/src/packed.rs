//! Translation between public RPC order methods and the authenticated packed hot path.

use codec::PackedOrder;

use crate::{Command, RpcMethod};

/// Lower a signed public RPC order method into the compact record shape.
///
/// `session_ref` is assigned only after the connection/session layer authenticates
/// the original [`crate::ControlMeta`] signer. Its outer batch authenticator then
/// binds the ordered packed bytes to that established identity, destination, and
/// batch sequence. Non-order RPC methods return `None` and continue to use the
/// generic codec.
#[must_use]
pub fn packed_order_from_method(method: &RpcMethod, session_ref: u32) -> Option<PackedOrder> {
    match method {
        RpcMethod::SubmitOrder(meta, p) => Some(PackedOrder::Submit {
            session_ref,
            nonce: meta.nonce,
            client_id: meta.client_id,
            account: p.account,
            market: p.market,
            side: p.side,
            order_type: p.order_type,
            price: p.price,
            quantity: p.quantity,
            time_in_force: p.time_in_force,
            leverage: p.leverage,
        }),
        RpcMethod::CancelOrder(meta, p) => Some(PackedOrder::Cancel {
            session_ref,
            nonce: meta.nonce,
            client_id: meta.client_id,
            account: p.account,
            market: p.market,
            order_id: p.order_id,
        }),
        RpcMethod::ReplaceOrder(meta, p) => Some(PackedOrder::Replace {
            session_ref,
            nonce: meta.nonce,
            client_id: meta.client_id,
            account: p.account,
            market: p.market,
            order_id: p.order_id,
            new_price: p.new_price,
            new_quantity: p.new_quantity,
        }),
        _ => None,
    }
}

/// Lower an already-authenticated packed record into the canonical engine command.
#[must_use]
pub fn command_from_packed_order(order: PackedOrder) -> Command {
    match order {
        PackedOrder::Submit {
            account,
            market,
            side,
            order_type,
            price,
            quantity,
            time_in_force,
            leverage,
            client_id: _,
            ..
        } => Command::PlaceOrder {
            account,
            market,
            side,
            order_type,
            price,
            quantity,
            time_in_force,
            leverage,
        },
        PackedOrder::Cancel {
            account,
            market,
            order_id,
            client_id: _,
            ..
        } => Command::CancelOrder {
            account,
            market,
            order_id,
        },
        PackedOrder::Replace {
            account,
            market,
            order_id,
            new_price,
            new_quantity,
            client_id: _,
            ..
        } => Command::ReplaceOrder {
            account,
            market,
            order_id,
            price: new_price,
            quantity: new_quantity,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancelOrderParams, ControlMeta, ReplaceOrderParams, SubmitOrderParams};
    use types::{
        AccountId, MarketId, OrderId, OrderType, Price, Quantity, Ratio, Side, TimeInForce,
    };

    fn meta(nonce: u64) -> ControlMeta {
        ControlMeta {
            client_id: 99,
            nonce,
            session_pubkey: None,
            signer: [1; 32],
            signature: [2; 64],
        }
    }

    #[test]
    fn rpc_order_variants_round_trip_to_the_same_canonical_command() {
        let methods = [
            RpcMethod::SubmitOrder(
                meta(1),
                SubmitOrderParams {
                    account: AccountId::new(2),
                    market: MarketId::new(3),
                    side: Side::Bid,
                    order_type: OrderType::Limit,
                    price: Price::from_raw(4),
                    quantity: Quantity::from_raw(5),
                    time_in_force: TimeInForce::Ioc,
                    leverage: Ratio::from_raw(1_000_000),
                },
            ),
            RpcMethod::CancelOrder(
                meta(2),
                CancelOrderParams {
                    account: AccountId::new(2),
                    market: MarketId::new(3),
                    order_id: OrderId::new(6),
                },
            ),
            RpcMethod::ReplaceOrder(
                meta(3),
                ReplaceOrderParams {
                    account: AccountId::new(2),
                    market: MarketId::new(3),
                    order_id: OrderId::new(6),
                    new_price: Price::from_raw(7),
                    new_quantity: Quantity::from_raw(8),
                },
            ),
        ];
        for method in methods {
            let expected = method.to_command().unwrap();
            let packed = packed_order_from_method(&method, 42).unwrap();
            assert_eq!(packed.session_ref(), 42);
            assert_eq!(command_from_packed_order(packed), expected);
        }
    }

    #[test]
    fn non_order_methods_stay_on_generic_codec() {
        assert_eq!(packed_order_from_method(&RpcMethod::GetNodeInfo, 1), None);
    }
}
