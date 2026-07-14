import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type AddressInfo } from "node:net";
import { test } from "node:test";

import {
  Ed25519Signer,
  MAX_PENDING_ORDER_BATCH_FINALITY,
  PackedClient,
  ProtocolError,
  decodeOrderBatchReceipt,
  decodeOrderBatchReceiptFrame,
  encodeAuthenticatedOrderBatch,
  encodeOrderBatchFrame,
  encodePackedOrder,
  encodeRawOrderBatch,
  type CancelOrder,
  type PackedLease,
} from "./index.js";
import { PendingFinalityCorrelations } from "./finality-correlation.js";

const cancel = (index: number): CancelOrder => ({
  kind: "cancel",
  sessionRef: 7,
  nonce: BigInt(index + 1),
  clientId: BigInt(index + 100),
  account: 9,
  market: 2,
  orderId: BigInt(index + 1000),
});

test("packed cancel and raw batch use the canonical layout", () => {
  const record = encodePackedOrder(cancel(0));
  assert.equal(record.length, 40);
  assert.equal(record.toString("hex"), "0102280007000000010000000000000064000000000000000900000002000000e803000000000000");
  const batch = encodeRawOrderBatch(Array.from({ length: 32 }, (_, index) => cancel(index)));
  assert.equal(batch.readUInt16LE(0), 0xb417);
  assert.equal(batch[3], 1);
  assert.equal(batch[5], 32);
  assert.equal(batch.readUInt32LE(8), 1280);
  assert.equal(batch.readUInt32LE(12), 1280);
});

test("authenticated batch is deterministic for a seed", () => {
  const signer = new Ed25519Signer(Uint8Array.from({ length: 32 }, () => 8));
  const records = Array.from({ length: 32 }, (_, index) => cancel(index));
  const encoded = encodeAuthenticatedOrderBatch(
    {
      destination: Uint8Array.from({ length: 32 }, () => 3),
      sessionRef: 7,
      account: 9,
      batchSequence: 4n,
      firstSequence: 100n,
    },
    signer,
    records,
  );
  assert.equal(signer.publicKey.toString("hex"), "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca");
  assert.equal(encoded.toString("ascii", 0, 4), "DXOB");
  assert.equal(encoded.readUInt32LE(96), 1300);
  assert.equal(encoded.length, 1464);
});

test("receipt semantic contradictions fail closed", () => {
  const receipt = Buffer.alloc(48);
  receipt.write("DXBR");
  receipt[4] = 1;
  receipt[5] = 2;
  receipt[6] = 32;
  receipt[7] = 32;
  receipt[8] = 31;
  receipt[10] = 1;
  assert.equal(decodeOrderBatchReceipt(receipt).stage, "executed");
  receipt[9] = 1;
  assert.throws(() => decodeOrderBatchReceipt(receipt), ProtocolError);
});

test("late-finality correlation preserves every key at the protocol bound", () => {
  assert.equal(MAX_PENDING_ORDER_BATCH_FINALITY, 65_536);
  const correlations = new PendingFinalityCorrelations();
  for (let index = 0; index < MAX_PENDING_ORDER_BATCH_FINALITY; index += 1) {
    assert.equal(correlations.retain(`batch-${index}`), true);
  }

  assert.equal(correlations.size, MAX_PENDING_ORDER_BATCH_FINALITY);
  assert.equal(correlations.canRetain, false);
  assert.equal(correlations.retain("overflow"), false);
  assert.equal(correlations.consume("overflow"), false);
  assert.equal(correlations.consume("batch-0"), true);
  assert.equal(correlations.retain("overflow"), true);
});

test("matches the shared packed-v1 golden vector", () => {
  const vector = JSON.parse(
    readFileSync(new URL("../../vectors/packed-v1.json", import.meta.url), "utf8"),
  ) as {
    expected: Record<string, string>;
  };
  const records = Array.from({ length: 32 }, (_, index) => cancel(index));
  const packed = Buffer.concat(records.map(encodePackedOrder));
  const raw = encodeRawOrderBatch(records);
  const signer = new Ed25519Signer(Buffer.alloc(32, 8));
  const authenticated = encodeAuthenticatedOrderBatch(
    {
      destination: Buffer.alloc(32, 3),
      sessionRef: 7,
      account: 9,
      batchSequence: 4n,
      firstSequence: 100n,
    },
    signer,
    records,
  );
  const digest = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
  assert.equal(packed.subarray(0, 40).toString("hex"), vector.expected.first_record_hex);
  assert.equal(digest(packed), vector.expected.packed_records_sha256);
  assert.equal(digest(raw), vector.expected.raw_order_batch_sha256);
  assert.equal(digest(authenticated), vector.expected.authenticated_batch_sha256);
  assert.equal(digest(encodeOrderBatchFrame(authenticated, 0n)), vector.expected.order_batch_frame_sha256);
  const receipt = decodeOrderBatchReceiptFrame(
    Buffer.from(vector.expected.executed_receipt_frame_hex ?? "", "hex"),
  );
  assert.equal(receipt.executed, 31);
  assert.equal(receipt.failed, 1);
});

test("PackedClient connects, signs, advances its lease, and reads receipts", async () => {
  let resolvePeer!: () => void;
  let rejectPeer!: (error: Error) => void;
  const peerDone = new Promise<void>((resolve, reject) => {
    resolvePeer = resolve;
    rejectPeer = reject;
  });
  const server = createServer((socket) => {
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      try {
        buffered = Buffer.concat([buffered, chunk]);
        if (buffered.length < 19) return;
        const length = buffered.readUInt32LE(15);
        if (buffered.length < 19 + length) return;
        const frame = buffered.subarray(0, 19 + length);
        assert.equal(frame.readUInt16LE(0), 0xde05);
        assert.equal(frame.readBigUInt64LE(7), 0n);
        const payload = frame.subarray(19);
        assert.equal(payload.toString("ascii", 0, 4), "DXOB");
        assert.equal(payload.readUInt32LE(40), 7);
        assert.equal(payload.readUInt32LE(44), 9);
        assert.equal(payload.readBigUInt64LE(48), 4n);
        assert.equal(payload.readBigUInt64LE(56), 100n);
        const bodyEnd = 100 + payload.readUInt32LE(96);
        const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
        const publicKey = createPublicKey({
          key: Buffer.concat([spkiPrefix, payload.subarray(64, 96)]),
          format: "der",
          type: "spki",
        });
        assert.equal(verify(null, payload.subarray(0, bodyEnd), publicKey, payload.subarray(bodyEnd)), true);
        socket.end(Buffer.concat([receiptFrame(1, 0n), receiptFrame(2, 1n)]), resolvePeer);
      } catch (error) {
        rejectPeer(error instanceof Error ? error : new Error(String(error)));
      }
    });
    socket.on("error", rejectPeer);
  });
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  const lease: PackedLease = {
    host: "127.0.0.1",
    port: address.port,
    destination: Buffer.alloc(32, 3),
    sessionRef: 7,
    account: 9,
    firstBatchSequence: 4n,
    firstCommandSequence: 100n,
    batchSequenceStride: 1n,
    commandSequenceStride: 0n,
  };
  const client = await PackedClient.connect(lease, Buffer.alloc(32, 8), { kind: "plaintext" });
  try {
    const result = await client.sendBatch(
      Array.from({ length: 32 }, (_, index) => cancel(index)),
      "executed",
      2_000,
    );
    assert.equal(result.batchSequence, 4n);
    assert.equal(result.executed.executed, 31);
    assert.equal(result.executed.failed, 1);
    assert.equal(client.nextBatchSequence, 5n);
    assert.equal(client.nextCommandSequence, 132n);
    await peerDone;
  } finally {
    client.close();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function receiptFrame(stage: 1 | 2, sequence: bigint): Buffer {
  const receipt = Buffer.alloc(48);
  receipt.write("DXBR", 0, "ascii");
  receipt[4] = 1;
  receipt[5] = stage;
  receipt[6] = 32;
  receipt[7] = 32;
  if (stage === 2) {
    receipt[8] = 31;
    receipt[10] = 1;
  }
  receipt.writeBigUInt64LE(4n, 16);
  receipt.writeBigUInt64LE(100n, 24);
  receipt.writeBigUInt64LE(123n, 40);
  const frame = Buffer.alloc(19 + receipt.length);
  frame.writeUInt16LE(0xde05, 0);
  frame.writeUInt16LE(1, 2);
  frame[4] = 4;
  frame.writeUInt16LE(0x0102, 5);
  frame.writeBigUInt64LE(sequence, 7);
  frame.writeUInt32LE(receipt.length, 15);
  receipt.copy(frame, 19);
  return frame;
}
