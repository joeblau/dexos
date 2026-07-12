// Byte-exchange transports. These move opaque frame bytes ONLY — no protocol
// logic lives here. Encoding requests and decoding responses is the wasm core's
// job (dexos-sdk-core); a transport just ships the exact postcard `Frame` to a
// node (or a gateway relay) and hands back the exact response frame.
//
// Mirrors the runtime-agnostic `Transport` seam in
// `crates/sdk-core/src/transport.rs`.

/** The single async byte-exchange seam. Implementors only move frame bytes. */
export interface Transport {
  exchange(framedRequest: Uint8Array): Promise<Uint8Array>;
}

/**
 * Browser / fetch transport talking to a `bin/dexos-gateway` relay. POSTs the
 * frame bytes verbatim to `POST {url}` and returns the response body bytes.
 * Suitable for the web (wasm) SDK build; carries no Node dependencies.
 */
export class GatewayTransport implements Transport {
  readonly url: string;
  private readonly init: RequestInit;

  constructor(url: string, init: RequestInit = {}) {
    this.url = url;
    this.init = init;
  }

  async exchange(framedRequest: Uint8Array): Promise<Uint8Array> {
    const res = await fetch(this.url, {
      ...this.init,
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        ...(this.init.headers ?? {}),
      },
      // Raw frame bytes as the request body. The cast bridges the TS 5.7
      // ArrayBuffer/ArrayBufferLike split between `Uint8Array` and DOM
      // `BufferSource`; no data is transformed.
      body: framedRequest as unknown as BodyInit,
    });
    if (!res.ok) {
      throw new Error(`gateway ${this.url} -> HTTP ${res.status} ${res.statusText}`);
    }
    return new Uint8Array(await res.arrayBuffer());
  }
}

/** The fixed postcard frame header length (codec::FRAME_HEADER_LEN). */
const FRAME_HEADER_LEN = 19;
/** Offset of the little-endian u32 payload length within the frame header. */
const PAYLOAD_LEN_OFFSET = 15;

export interface NodeTcpOptions {
  host: string;
  port: number;
  /** TLS 1.3 (default). Set false only for local plaintext dev nodes. */
  tls?: boolean;
  /** SNI server name for the TLS handshake; defaults to `host`. */
  serverName?: string;
}

/**
 * Node.js TCP / TLS transport. Writes the request frame, then reads EXACTLY one
 * response frame (fixed 19-byte header, then the LE u32 payload length),
 * matching the node's one-frame-per-request model and
 * `crates/sdk/src/tls.rs`. Node built-ins are imported lazily so this module
 * stays importable in browser/bundler builds.
 */
export class NodeTcpTransport implements Transport {
  private readonly opts: NodeTcpOptions;

  constructor(opts: NodeTcpOptions) {
    this.opts = opts;
  }

  async exchange(framedRequest: Uint8Array): Promise<Uint8Array> {
    const { host, port, tls: useTls = true, serverName } = this.opts;
    const socket = useTls
      ? (await import("node:tls")).connect({
          host,
          port,
          servername: serverName ?? host,
          minVersion: "TLSv1.3",
        })
      : (await import("node:net")).connect({ host, port });

    return await new Promise<Uint8Array>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let need = -1; // total frame length once the header is seen

      const cleanup = (): void => {
        socket.off("data", onData);
        socket.off("error", onError);
        socket.off("close", onClose);
      };
      const onData = (chunk: Buffer): void => {
        chunks.push(chunk);
        const buf = Buffer.concat(chunks);
        if (need < 0 && buf.length >= FRAME_HEADER_LEN) {
          const plen = buf.readUInt32LE(PAYLOAD_LEN_OFFSET);
          need = FRAME_HEADER_LEN + plen;
        }
        if (need >= 0 && buf.length >= need) {
          cleanup();
          socket.end();
          resolve(new Uint8Array(buf.subarray(0, need)));
        }
      };
      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };
      const onClose = (): void => {
        cleanup();
        reject(new Error("connection closed before a full response frame"));
      };

      socket.on("data", onData);
      socket.once("error", onError);
      socket.once("close", onClose);

      const write = (): void => {
        socket.write(framedRequest);
      };
      // `secureConnect` for TLS, `connect` for plaintext; the generic event
      // overload on Duplex accepts either name.
      socket.once(useTls ? "secureConnect" : "connect", write);
    });
  }
}
