//! Framing of requests, responses, and stream events into `codec::Frame`s for
//! the compact binary wire. All decode paths are total (never panic).

use codec::{Frame, TrafficClass};

use crate::error::RpcError;
use crate::request::RpcRequest;
use crate::response::RpcResponse;
use crate::stream::StreamEvent;

/// Frame `msg_type` tag for an RPC request.
pub const MSG_REQUEST: u16 = 1;
/// Frame `msg_type` tag for an RPC response.
pub const MSG_RESPONSE: u16 = 2;
/// Frame `msg_type` tag for a stream event.
pub const MSG_STREAM_EVENT: u16 = 3;

/// Encode a request into a framed byte buffer. Control requests are tagged with
/// a higher-priority traffic class than queries so they are not starved by
/// market-data reads.
pub fn encode_request(request: &RpcRequest) -> Result<Vec<u8>, RpcError> {
    let payload = codec::encode(request)?;
    let class = if request.is_control() {
        TrafficClass::NewOrder
    } else {
        TrafficClass::MarketData
    };
    let frame = Frame {
        class,
        msg_type: MSG_REQUEST,
        sequence: request.request_id,
        payload,
    };
    frame.encode().map_err(RpcError::from)
}

/// Decode a framed request. Returns [`RpcError::InvalidRequest`] on a wrong
/// message type, and never panics on arbitrary bytes.
pub fn decode_request(bytes: &[u8]) -> Result<RpcRequest, RpcError> {
    let (frame, _) = Frame::decode(bytes).map_err(RpcError::from)?;
    if frame.msg_type != MSG_REQUEST {
        return Err(RpcError::InvalidRequest("expected request frame".into()));
    }
    codec::decode(&frame.payload).map_err(RpcError::from)
}

/// Encode a response into a framed byte buffer.
pub fn encode_response(response: &RpcResponse) -> Result<Vec<u8>, RpcError> {
    let payload = codec::encode(response)?;
    let frame = Frame {
        class: TrafficClass::MarketData,
        msg_type: MSG_RESPONSE,
        sequence: response.request_id,
        payload,
    };
    frame.encode().map_err(RpcError::from)
}

/// Decode a framed response. Never panics on arbitrary bytes.
pub fn decode_response(bytes: &[u8]) -> Result<RpcResponse, RpcError> {
    let (frame, _) = Frame::decode(bytes).map_err(RpcError::from)?;
    if frame.msg_type != MSG_RESPONSE {
        return Err(RpcError::InvalidRequest("expected response frame".into()));
    }
    codec::decode(&frame.payload).map_err(RpcError::from)
}

/// Encode a stream event into a framed byte buffer, tagging market-data events
/// with the market-data traffic class so they cannot starve consensus traffic.
pub fn encode_stream_event(event: &StreamEvent) -> Result<Vec<u8>, RpcError> {
    let payload = codec::encode(event)?;
    let frame = Frame {
        class: TrafficClass::MarketData,
        msg_type: MSG_STREAM_EVENT,
        sequence: event.sequence.get(),
        payload,
    };
    frame.encode().map_err(RpcError::from)
}

/// Decode a framed stream event. Never panics on arbitrary bytes.
pub fn decode_stream_event(bytes: &[u8]) -> Result<StreamEvent, RpcError> {
    let (frame, _) = Frame::decode(bytes).map_err(RpcError::from)?;
    if frame.msg_type != MSG_STREAM_EVENT {
        return Err(RpcError::InvalidRequest("expected stream frame".into()));
    }
    codec::decode(&frame.payload).map_err(RpcError::from)
}
