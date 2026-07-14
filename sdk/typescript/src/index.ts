import {
  createPrivateKey,
  createPublicKey,
  sign,
  type KeyObject,
} from "node:crypto";
import { connect as connectTcp, type Socket, type TcpNetConnectOpts } from "node:net";
import {
  connect as connectTls,
  type ConnectionOptions as TlsConnectionOptions,
  type TLSSocket,
} from "node:tls";

import {
  MAX_PENDING_ORDER_BATCH_FINALITY,
  PendingFinalityCorrelations,
} from "./finality-correlation.js";

export { MAX_PENDING_ORDER_BATCH_FINALITY } from "./finality-correlation.js";

const FRAME_HEADER_LEN = 19;
const RECEIPT_LEN = 48;
const MSG_TYPE_ORDER_BATCH = 0x0101;
const MSG_TYPE_ORDER_BATCH_RECEIPT = 0x0102;
const TRAFFIC_NEW_ORDER = 3;
const TRAFFIC_EXECUTION_RECEIPT = 4;

export type Side = "bid" | "ask";
export type OrderType = "limit" | "market" | "post-only" | "reduce-only";
export type TimeInForce = "gtc" | "ioc" | "fok";

interface CommonOrder {
  sessionRef: number;
  nonce: bigint;
  clientId: bigint;
  account: number;
  market: number;
}

export interface SubmitOrder extends CommonOrder {
  kind: "submit";
  side: Side;
  orderType: OrderType;
  price: bigint;
  quantity: bigint;
  timeInForce: TimeInForce;
  leverage: bigint;
}

export interface CancelOrder extends CommonOrder {
  kind: "cancel";
  orderId: bigint;
}

export interface ReplaceOrder extends CommonOrder {
  kind: "replace";
  orderId: bigint;
  newPrice: bigint;
  newQuantity: bigint;
}

export type PackedOrder = SubmitOrder | CancelOrder | ReplaceOrder;

export interface PackedLease {
  host: string;
  port: number;
  sourceAddress?: string;
  destination: Uint8Array;
  sessionRef: number;
  account: number;
  firstBatchSequence: bigint;
  firstCommandSequence: bigint;
  batchSequenceStride: bigint;
  /** Zero selects contiguous advancement by the record count. */
  commandSequenceStride: bigint;
}

export type PackedTransport =
  | { kind: "plaintext" }
  | {
      kind: "tls13";
      serverName: string;
      ca: string | Buffer | (string | Buffer)[];
      cert?: string | Buffer;
      key?: string | Buffer;
    };

export type ReceiptStage = "admitted" | "executed" | "finalized" | "rejected";

export interface OrderBatchReceipt {
  stage: ReceiptStage;
  recordCount: number;
  admitted: number;
  executed: number;
  finalized: number;
  failed: number;
  rejectionCode: number;
  batchSequence: bigint;
  firstSequence: bigint;
  checkpointHeight?: bigint;
  observedUnixNs: bigint;
}

export interface PackedBatchResult {
  batchSequence: bigint;
  firstSequence: bigint;
  admitted?: OrderBatchReceipt;
  executed: OrderBatchReceipt;
  finalized?: OrderBatchReceipt;
}

/** An Ed25519 key backed by a canonical 32-byte seed. */
export class Ed25519Signer {
  readonly publicKey: Buffer;
  readonly #privateKey: KeyObject;

  constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new ProtocolError("signing seed must contain 32 bytes");
    const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    this.#privateKey = createPrivateKey({
      key: Buffer.concat([prefix, Buffer.from(seed)]),
      format: "der",
      type: "pkcs8",
    });
    const spki = createPublicKey(this.#privateKey).export({ format: "der", type: "spki" });
    this.publicKey = Buffer.from(spki).subarray(-32);
  }

  sign(message: Uint8Array): Buffer {
    return sign(null, Buffer.from(message), this.#privateKey);
  }
}

export function encodePackedOrder(order: PackedOrder): Buffer {
  const tag = order.kind === "submit" ? 1 : order.kind === "cancel" ? 2 : 3;
  const length = order.kind === "cancel" ? 40 : 56;
  const out = Buffer.alloc(length);
  out[0] = 1;
  out[1] = tag;
  out[2] = length;
  out[3] = order.kind === "submit" ? submitFlags(order) : 0;
  writeU32(out, 4, order.sessionRef, "sessionRef");
  writeU64(out, 8, order.nonce, "nonce");
  writeU64(out, 16, order.clientId, "clientId");
  writeU32(out, 24, order.account, "account");
  writeU32(out, 28, order.market, "market");
  if (order.kind === "submit") {
    writeI64(out, 32, order.price, "price");
    writeI64(out, 40, order.quantity, "quantity");
    writeI64(out, 48, order.leverage, "leverage");
  } else if (order.kind === "cancel") {
    writeU64(out, 32, order.orderId, "orderId");
  } else {
    writeU64(out, 32, order.orderId, "orderId");
    writeI64(out, 40, order.newPrice, "newPrice");
    writeI64(out, 48, order.newQuantity, "newQuantity");
  }
  return out;
}

/** Encode the interoperable raw (uncompressed) v1 order-batch envelope. */
export function encodeRawOrderBatch(records: readonly PackedOrder[]): Buffer {
  validateBatch(records);
  const packed = Buffer.concat(records.map(encodePackedOrder));
  const out = Buffer.alloc(20 + packed.length);
  out.writeUInt16LE(0xb417, 0);
  out[2] = 1;
  out[3] = 1; // FLAG_RAW, never partial.
  out[4] = 0; // Raw/scalar backend.
  out[5] = records.length;
  out.writeUInt32LE(packed.length, 8);
  out.writeUInt32LE(packed.length, 12);
  out.writeUInt32LE(crc32(packed), 16);
  packed.copy(out, 20);
  return out;
}

export interface BatchBinding {
  destination: Uint8Array;
  sessionRef: number;
  account: number;
  batchSequence: bigint;
  firstSequence: bigint;
}

export function encodeAuthenticatedOrderBatch(
  binding: BatchBinding,
  signer: Ed25519Signer,
  records: readonly PackedOrder[],
): Buffer {
  if (binding.destination.length !== 32) {
    throw new ProtocolError("destination must contain 32 bytes");
  }
  validateRecordBindings(records, binding.sessionRef, binding.account);
  const inner = encodeRawOrderBatch(records);
  const body = Buffer.alloc(100 + inner.length);
  body.write("DXOB", 0, "ascii");
  body[4] = 1;
  Buffer.from(binding.destination).copy(body, 8);
  writeU32(body, 40, binding.sessionRef, "sessionRef");
  writeU32(body, 44, binding.account, "account");
  writeU64(body, 48, binding.batchSequence, "batchSequence");
  writeU64(body, 56, binding.firstSequence, "firstSequence");
  signer.publicKey.copy(body, 64);
  body.writeUInt32LE(inner.length, 96);
  inner.copy(body, 100);
  return Buffer.concat([body, signer.sign(body)]);
}

export function encodeOrderBatchFrame(payload: Uint8Array, sequence: bigint): Buffer {
  return encodeFrame(TRAFFIC_NEW_ORDER, MSG_TYPE_ORDER_BATCH, sequence, payload);
}

export function decodeOrderBatchReceiptFrame(frame: Uint8Array): OrderBatchReceipt {
  const bytes = Buffer.from(frame);
  if (bytes.length < FRAME_HEADER_LEN) throw new ProtocolError("truncated frame");
  validateFrameHeader(bytes.subarray(0, FRAME_HEADER_LEN));
  if (bytes[4] !== TRAFFIC_EXECUTION_RECEIPT) {
    throw new ProtocolError("receipt has the wrong traffic class");
  }
  if (bytes.readUInt16LE(5) !== MSG_TYPE_ORDER_BATCH_RECEIPT) {
    throw new ProtocolError("receipt has the wrong message type");
  }
  const length = bytes.readUInt32LE(15);
  if (length !== RECEIPT_LEN || bytes.length !== FRAME_HEADER_LEN + length) {
    throw new ProtocolError("receipt frame length is invalid");
  }
  return decodeOrderBatchReceipt(bytes.subarray(FRAME_HEADER_LEN));
}

export function decodeOrderBatchReceipt(payload: Uint8Array): OrderBatchReceipt {
  const bytes = Buffer.from(payload);
  if (bytes.length !== RECEIPT_LEN) throw new ProtocolError("receipt must contain 48 bytes");
  if (bytes.toString("ascii", 0, 4) !== "DXBR") throw new ProtocolError("bad receipt magic");
  if (bytes[4] !== 1) throw new ProtocolError(`unsupported receipt version ${String(bytes[4])}`);
  const rawStage = bytes[5];
  const stage: ReceiptStage =
    rawStage === 1
      ? "admitted"
      : rawStage === 2
        ? "executed"
        : rawStage === 3
          ? "finalized"
          : rawStage === 4
            ? "rejected"
            : (() => {
                throw new ProtocolError(`unknown receipt stage ${String(rawStage)}`);
              })();
  const flags = bytes[11] ?? 0;
  if ((flags & ~1) !== 0 || bytes[14] !== 0 || bytes[15] !== 0) {
    throw new ProtocolError("receipt reserved bits are nonzero");
  }
  const receipt: OrderBatchReceipt = {
    stage,
    recordCount: bytes[6] ?? 0,
    admitted: bytes[7] ?? 0,
    executed: bytes[8] ?? 0,
    finalized: bytes[9] ?? 0,
    failed: bytes[10] ?? 0,
    rejectionCode: bytes.readUInt16LE(12),
    batchSequence: bytes.readBigUInt64LE(16),
    firstSequence: bytes.readBigUInt64LE(24),
    ...(flags === 1 ? { checkpointHeight: bytes.readBigUInt64LE(32) } : {}),
    observedUnixNs: bytes.readBigUInt64LE(40),
  };
  validateReceipt(receipt);
  return receipt;
}

/** A serialized persistent client. Use one instance per server-issued lease. */
export class PackedClient {
  readonly publicKey: Buffer;
  readonly #lease: PackedLease;
  readonly #signer: Ed25519Signer;
  readonly #reader: BufferedSocket;
  #nextTransportSequence = 0n;
  #nextReceiptSequence = 0n;
  #nextBatchSequence: bigint;
  #nextCommandSequence: bigint;
  readonly #retiredExecuted = new PendingFinalityCorrelations();
  #sending = false;
  #usable = true;

  private constructor(lease: PackedLease, signer: Ed25519Signer, socket: Socket | TLSSocket) {
    validateLease(lease);
    this.#lease = lease;
    this.#signer = signer;
    this.publicKey = signer.publicKey;
    this.#reader = new BufferedSocket(socket);
    this.#nextBatchSequence = lease.firstBatchSequence;
    this.#nextCommandSequence = lease.firstCommandSequence;
  }

  static async connect(
    lease: PackedLease,
    signingSeed: Uint8Array,
    transport: PackedTransport,
  ): Promise<PackedClient> {
    validateLease(lease);
    const socket = await openSocket(lease, transport);
    return new PackedClient(lease, new Ed25519Signer(signingSeed), socket);
  }

  get nextBatchSequence(): bigint {
    return this.#nextBatchSequence;
  }

  get nextCommandSequence(): bigint {
    return this.#nextCommandSequence;
  }

  close(): void {
    this.#reader.destroy();
  }

  async sendBatch(
    records: readonly PackedOrder[],
    completion: "executed" | "finalized" = "executed",
    timeoutMs = 10_000,
  ): Promise<PackedBatchResult> {
    if (this.#sending) throw new ProtocolError("concurrent sendBatch calls are not supported");
    if (!this.#usable) {
      throw new ProtocolError("connection is unusable after an ambiguous in-flight failure");
    }
    if (completion !== "executed" && completion !== "finalized") {
      throw new ProtocolError("completion must be executed or finalized");
    }
    if (completion === "executed" && !this.#retiredExecuted.canRetain) {
      throw new ProtocolError(
        `pending finality correlation capacity ${MAX_PENDING_ORDER_BATCH_FINALITY} is exhausted`,
      );
    }
    this.#sending = true;
    try {
      validateRecordBindings(records, this.#lease.sessionRef, this.#lease.account);
      const binding: BatchBinding = {
        destination: this.#lease.destination,
        sessionRef: this.#lease.sessionRef,
        account: this.#lease.account,
        batchSequence: this.#nextBatchSequence,
        firstSequence: this.#nextCommandSequence,
      };
      const payload = encodeAuthenticatedOrderBatch(binding, this.#signer, records);
      const wire = encodeOrderBatchFrame(payload, this.#nextTransportSequence);
      this.#usable = false;
      await this.#reader.write(wire);
      const commandAdvance =
        this.#lease.commandSequenceStride === 0n
          ? BigInt(records.length)
          : this.#lease.commandSequenceStride;
      if (commandAdvance < BigInt(records.length)) throw new ProtocolError("invalid command stride");
      this.#nextTransportSequence = checkedAdd(this.#nextTransportSequence, 1n, "transport sequence");
      this.#nextBatchSequence = checkedAdd(
        this.#nextBatchSequence,
        this.#lease.batchSequenceStride,
        "batch sequence",
      );
      this.#nextCommandSequence = checkedAdd(
        this.#nextCommandSequence,
        commandAdvance,
        "command sequence",
      );

      let admitted: OrderBatchReceipt | undefined;
      let executed: OrderBatchReceipt | undefined;
      for (;;) {
        const { sequence, receipt } = await withTimeout(this.#readReceipt(), timeoutMs, () =>
          this.#reader.destroy(),
        );
        if (sequence !== this.#nextReceiptSequence) {
          throw new ProtocolError(
            `receipt sequence mismatch: expected ${this.#nextReceiptSequence}, got ${sequence}`,
          );
        }
        this.#nextReceiptSequence = checkedAdd(this.#nextReceiptSequence, 1n, "receipt sequence");
        const key = receiptKey(receipt.batchSequence, receipt.firstSequence);
        const currentKey = receiptKey(binding.batchSequence, binding.firstSequence);
        if (key !== currentKey) {
          if (receipt.stage === "finalized" && this.#retiredExecuted.consume(key)) {
            continue;
          }
          throw new ProtocolError(`uncorrelated receipt ${key}`);
        }
        if (receipt.recordCount !== records.length) throw new ProtocolError("receipt count mismatch");
        if (receipt.stage === "rejected") {
          throw new BatchRejectedError(receipt.rejectionCode);
        } else if (receipt.stage === "admitted") {
          admitted = receipt;
        } else if (receipt.stage === "executed") {
          executed = receipt;
          if (completion === "executed") {
            if (!this.#retiredExecuted.retain(key)) {
              throw new ProtocolError("executed batch could not be retained for late finality");
            }
            this.#usable = true;
            return {
              batchSequence: binding.batchSequence,
              firstSequence: binding.firstSequence,
              ...(admitted === undefined ? {} : { admitted }),
              executed: receipt,
            };
          }
        } else {
          if (executed === undefined) throw new ProtocolError("finalized receipt preceded execution");
          this.#usable = true;
          return {
            batchSequence: binding.batchSequence,
            firstSequence: binding.firstSequence,
            ...(admitted === undefined ? {} : { admitted }),
            executed,
            finalized: receipt,
          };
        }
      }
    } finally {
      this.#sending = false;
    }
  }

  async #readReceipt(): Promise<{ sequence: bigint; receipt: OrderBatchReceipt }> {
    const header = await this.#reader.readExactly(FRAME_HEADER_LEN);
    validateFrameHeader(header);
    const length = header.readUInt32LE(15);
    if (length !== RECEIPT_LEN) throw new ProtocolError("receipt frame length is invalid");
    if (header[4] !== TRAFFIC_EXECUTION_RECEIPT || header.readUInt16LE(5) !== MSG_TYPE_ORDER_BATCH_RECEIPT) {
      throw new ProtocolError("frame is not a packed batch receipt");
    }
    const payload = await this.#reader.readExactly(length);
    return { sequence: header.readBigUInt64LE(7), receipt: decodeOrderBatchReceipt(payload) };
  }
}

export class ProtocolError extends Error {}

export class BatchRejectedError extends ProtocolError {
  constructor(readonly rejectionCode: number) {
    super(`batch rejected with code ${rejectionCode}`);
  }
}

function submitFlags(order: SubmitOrder): number {
  const side = order.side === "bid" ? 0 : order.side === "ask" ? 1 : invalidEnum("side");
  const orderType =
    order.orderType === "limit"
      ? 0
      : order.orderType === "market"
        ? 1
        : order.orderType === "post-only"
          ? 2
          : order.orderType === "reduce-only"
            ? 3
            : invalidEnum("orderType");
  const tif =
    order.timeInForce === "gtc"
      ? 0
      : order.timeInForce === "ioc"
        ? 1
        : order.timeInForce === "fok"
          ? 2
          : invalidEnum("timeInForce");
  return side | (orderType << 1) | (tif << 3);
}

function invalidEnum(name: string): never {
  throw new ProtocolError(`invalid ${name}`);
}

function validateBatch(records: readonly PackedOrder[]): void {
  if (records.length < 32 || records.length > 128) {
    throw new ProtocolError(`batch size ${records.length} is outside 32..=128`);
  }
}

function validateRecordBindings(records: readonly PackedOrder[], sessionRef: number, account: number): void {
  validateBatch(records);
  for (const record of records) {
    if (record.sessionRef !== sessionRef || record.account !== account) {
      throw new ProtocolError("record does not match the batch session/account binding");
    }
  }
}

function validateLease(lease: PackedLease): void {
  if (lease.destination.length !== 32) throw new ProtocolError("destination must contain 32 bytes");
  if (!Number.isInteger(lease.port) || lease.port < 1 || lease.port > 65535) {
    throw new ProtocolError("port is outside 1..=65535");
  }
  writeU32(Buffer.alloc(4), 0, lease.sessionRef, "sessionRef");
  writeU32(Buffer.alloc(4), 0, lease.account, "account");
  if (lease.batchSequenceStride <= 0n) throw new ProtocolError("batch stride must be positive");
  if (lease.commandSequenceStride < 0n) throw new ProtocolError("command stride cannot be negative");
}

function validateReceipt(receipt: OrderBatchReceipt): void {
  const count = receipt.recordCount;
  if (count < 32 || count > 128) throw new ProtocolError("receipt record count is invalid");
  if (
    receipt.admitted > count ||
    receipt.executed > receipt.admitted ||
    receipt.finalized > receipt.executed ||
    receipt.failed > receipt.admitted ||
    receipt.executed + receipt.failed > receipt.admitted
  ) {
    throw new ProtocolError("receipt counters do not conserve");
  }
  const noCheckpoint = receipt.checkpointHeight === undefined;
  const valid =
    (receipt.stage === "admitted" &&
      receipt.admitted === count &&
      receipt.executed === 0 &&
      receipt.finalized === 0 &&
      receipt.failed === 0 &&
      receipt.rejectionCode === 0 &&
      noCheckpoint) ||
    (receipt.stage === "executed" &&
      receipt.admitted === count &&
      receipt.executed + receipt.failed === receipt.admitted &&
      receipt.finalized === 0 &&
      receipt.rejectionCode === 0 &&
      noCheckpoint) ||
    (receipt.stage === "finalized" &&
      receipt.admitted === count &&
      receipt.executed + receipt.failed === receipt.admitted &&
      receipt.finalized === receipt.executed &&
      receipt.rejectionCode === 0 &&
      !noCheckpoint) ||
    (receipt.stage === "rejected" &&
      receipt.admitted === 0 &&
      receipt.executed === 0 &&
      receipt.finalized === 0 &&
      receipt.failed === 0 &&
      receipt.rejectionCode !== 0 &&
      noCheckpoint);
  if (!valid) throw new ProtocolError("receipt contradicts its lifecycle stage");
}

function encodeFrame(trafficClass: number, messageType: number, sequence: bigint, payload: Uint8Array): Buffer {
  if (payload.length > 0xffff_ffff) throw new ProtocolError("frame payload is too large");
  const out = Buffer.alloc(FRAME_HEADER_LEN + payload.length);
  out.writeUInt16LE(0xde05, 0);
  out.writeUInt16LE(1, 2);
  out[4] = trafficClass;
  out.writeUInt16LE(messageType, 5);
  writeU64(out, 7, sequence, "frame sequence");
  out.writeUInt32LE(payload.length, 15);
  Buffer.from(payload).copy(out, FRAME_HEADER_LEN);
  return out;
}

function validateFrameHeader(header: Buffer): void {
  if (header.length !== FRAME_HEADER_LEN) throw new ProtocolError("frame header must contain 19 bytes");
  if (header.readUInt16LE(0) !== 0xde05) throw new ProtocolError("bad frame magic");
  if (header.readUInt16LE(2) !== 1) throw new ProtocolError("unsupported frame version");
}

function writeU32(out: Buffer, offset: number, value: number, name: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ProtocolError(`${name} is outside unsigned 32-bit range`);
  }
  out.writeUInt32LE(value, offset);
}

function writeU64(out: Buffer, offset: number, value: bigint, name: string): void {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new ProtocolError(`${name} is outside unsigned 64-bit range`);
  }
  out.writeBigUInt64LE(value, offset);
}

function writeI64(out: Buffer, offset: number, value: bigint, name: string): void {
  if (value < -0x8000_0000_0000_0000n || value > 0x7fff_ffff_ffff_ffffn) {
    throw new ProtocolError(`${name} is outside signed 64-bit range`);
  }
  out.writeBigInt64LE(value, offset);
}

function checkedAdd(left: bigint, right: bigint, name: string): bigint {
  const result = left + right;
  if (result < 0n || result > 0xffff_ffff_ffff_ffffn) {
    throw new ProtocolError(`${name} exhausted`);
  }
  return result;
}

function crc32(data: Uint8Array): number {
  let crc = 0xffff_ffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb8_8320 : 0);
    }
  }
  return (crc ^ 0xffff_ffff) >>> 0;
}

function receiptKey(batch: bigint, first: bigint): string {
  return `${batch}:${first}`;
}

async function openSocket(lease: PackedLease, transport: PackedTransport): Promise<Socket | TLSSocket> {
  if (transport.kind === "plaintext") {
    const options: TcpNetConnectOpts = {
      host: lease.host,
      port: lease.port,
      ...(lease.sourceAddress === undefined ? {} : { localAddress: lease.sourceAddress }),
    };
    const socket = connectTcp(options);
    await onceConnected(socket, "connect");
    socket.setNoDelay(true);
    return socket;
  }
  const options: TlsConnectionOptions = {
    host: lease.host,
    port: lease.port,
    servername: transport.serverName,
    ca: transport.ca,
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    ALPNProtocols: ["dexos-rpc/1"],
    ...(lease.sourceAddress === undefined ? {} : { localAddress: lease.sourceAddress }),
    ...(transport.cert === undefined ? {} : { cert: transport.cert }),
    ...(transport.key === undefined ? {} : { key: transport.key }),
  };
  const socket = connectTls(options);
  await onceConnected(socket, "secureConnect");
  socket.setNoDelay(true);
  return socket;
}

function onceConnected(socket: Socket | TLSSocket, event: "connect" | "secureConnect"): Promise<void> {
  return new Promise((resolve, reject) => {
    const onConnect = (): void => {
      cleanup();
      resolve();
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const cleanup = (): void => {
      socket.off(event, onConnect);
      socket.off("error", onError);
    };
    socket.once(event, onConnect);
    socket.once("error", onError);
  });
}

class BufferedSocket {
  readonly #socket: Socket | TLSSocket;
  #buffer = Buffer.alloc(0);
  #ended: Error | undefined;
  #waiter: (() => void) | undefined;

  constructor(socket: Socket | TLSSocket) {
    this.#socket = socket;
    socket.on("data", (chunk: Buffer) => {
      this.#buffer = Buffer.concat([this.#buffer, chunk]);
      this.#wake();
    });
    socket.on("error", (error) => {
      this.#ended = error;
      this.#wake();
    });
    socket.on("close", () => {
      this.#ended ??= new Error("socket closed");
      this.#wake();
    });
  }

  destroy(): void {
    this.#socket.destroy();
  }

  write(bytes: Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
      this.#socket.write(bytes, (error?: Error | null) => {
        if (error != null) reject(error);
        else resolve();
      });
    });
  }

  async readExactly(length: number): Promise<Buffer> {
    while (this.#buffer.length < length) {
      if (this.#ended !== undefined) throw this.#ended;
      await new Promise<void>((resolve) => {
        this.#waiter = resolve;
      });
    }
    const result = this.#buffer.subarray(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return result;
  }

  #wake(): void {
    const waiter = this.#waiter;
    this.#waiter = undefined;
    waiter?.();
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, onTimeout: () => void): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new ProtocolError("timeout must be positive");
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => {
          onTimeout();
          reject(new ProtocolError("receipt deadline elapsed"));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
