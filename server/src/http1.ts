import { connect } from 'cloudflare:sockets';

// One HTTP/1.1 POST over its own socket, so the caller can read trailers, which fetch() drops.
// It frames the response and passes every body byte through unchanged; it never decodes the body.

export type Target = { hostname: string; port: number; tls: boolean };
export type Http1Response = {
  status: number;
  /** Lower-cased names; at most 16 KiB of header block. */
  headers: Headers;
  /** De-chunked bytes, unchanged; errors on bad framing or more than 16 MiB. */
  body: ReadableStream<Uint8Array>;
  /** After the body ends; null if none, cut or larger than 8 KiB. */
  trailers: Promise<Headers | null>;
};

const MAX_HEAD = 16 * 1024;
const MAX_CHUNK_LINE = 1024;
const MAX_TRAILERS = 8 * 1024;
const MAX_BODY = 16 * 1024 * 1024;
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const text = new TextDecoder();

/** A socket's bytes: framing lines, and body bytes as they arrive. */
class Bytes {
  private buffer: Uint8Array = new Uint8Array(0);
  constructor(private readonly reader: ReadableStreamDefaultReader<Uint8Array>) {}
  private async more(): Promise<boolean> {
    const { value, done } = await this.reader.read();
    if (done) return false;
    if (this.buffer.length === 0) {
      this.buffer = value;
    } else {
      const joined = new Uint8Array(this.buffer.length + value.length);
      joined.set(this.buffer);
      joined.set(value, this.buffer.length);
      this.buffer = joined;
    }
    return true;
  }
  /** The next line without its line ending; throws if it is longer than max or the stream ends first. */
  async line(max: number): Promise<string> {
    let from = 0;
    while (true) {
      const end = this.buffer.indexOf(10, from);
      if (end > max || (end < 0 && this.buffer.length > max)) throw new Error('line too long');
      if (end >= 0) {
        const line = this.buffer.subarray(0, end > 0 && this.buffer[end - 1] === 13 ? end - 1 : end);
        this.buffer = this.buffer.subarray(end + 1);
        return text.decode(line);
      }
      from = this.buffer.length;
      if (!await this.more()) throw new Error('cut');
    }
  }
  /** Up to max bytes as they arrive; null at the end of the stream. */
  async take(max: number): Promise<Uint8Array | null> {
    if (this.buffer.length === 0 && !await this.more()) return null;
    const taken = this.buffer.slice(0, max);
    this.buffer = this.buffer.subarray(taken.length);
    return taken;
  }
  cancel(): void { this.reader.cancel().catch(() => {}); }
}

/** Header fields up to the empty line, within budget bytes. */
async function fields(bytes: Bytes, budget: number): Promise<Headers> {
  const headers = new Headers();
  while (true) {
    const line = await bytes.line(budget);
    budget -= line.length + 2;
    if (budget < 0) throw new Error('header block too large');
    if (line === '') return headers;
    const colon = line.indexOf(':');
    if (colon < 1 || !TOKEN.test(line.slice(0, colon))) throw new Error('bad header');
    const name = line.slice(0, colon), value = line.slice(colon + 1).trim();
    // Tinfoil repeats its usage trailer with the same value. Keep one copy; differing
    // copies stay joined, so usage fails to parse and the call counts as unreported.
    if (headers.get(name) !== value) headers.append(name, value);
  }
}

type Framing = { chunked: true } | { chunked: false; length: number | null };

function framing(status: number, headers: Headers): Framing {
  const coding = headers.get('transfer-encoding');
  const length = headers.get('content-length');
  if (coding !== null && length !== null) throw new Error('two framings');
  if (status === 204 || status === 304) return { chunked: false, length: 0 };
  if (coding !== null) {
    if (coding.toLowerCase() !== 'chunked') throw new Error('unsupported transfer coding');
    return { chunked: true };
  }
  if (length === null) return { chunked: false, length: null };
  if (!/^\d{1,9}$/.test(length) || Number(length) > MAX_BODY) throw new Error('bad content length');
  return { chunked: false, length: Number(length) };
}

function body(bytes: Bytes, framed: Framing, settle: (trailers: Headers | null) => void,
    close: () => void): ReadableStream<Uint8Array> {
  // Bytes left in the current chunk, or in the whole body; null reads to the end of the stream.
  let left: number | null = framed.chunked ? 0 : framed.length;
  let chunks = 0;
  let total = 0;
  const end = (controller: ReadableStreamDefaultController<Uint8Array>, trailers: Headers | null) => {
    settle(trailers);
    close();
    controller.close();
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        if (framed.chunked && left === 0) {
          if (chunks++ > 0 && await bytes.line(2) !== '') throw new Error('bad chunk end');
          const size = /^([0-9a-fA-F]{1,8})(?:[ \t]*;.*)?$/.exec(await bytes.line(MAX_CHUNK_LINE));
          if (!size) throw new Error('bad chunk size');
          left = parseInt(size[1], 16);
          if (left === 0) {
            // The body is complete; usage that doesn't arrive whole stays unreported.
            end(controller, await fields(bytes, MAX_TRAILERS).catch(() => null));
            return;
          }
        }
        if (left === 0) { end(controller, null); return; }
        const data = await bytes.take(left ?? MAX_BODY);
        if (data === null) {
          if (left !== null) throw new Error('cut');
          end(controller, null);
          return;
        }
        total += data.length;
        if (total > MAX_BODY) throw new Error('body too large');
        if (left !== null) left -= data.length;
        controller.enqueue(data);
      } catch (error) {
        settle(null);
        close();
        controller.error(error);
      }
    },
    cancel() {
      settle(null);
      close();
    },
  }, { highWaterMark: 0 });
}

export async function post(target: Target, path: string, headers: [string, string][],
    payload: Uint8Array): Promise<Http1Response> {
  if (headers.some(([name, value]) => !TOKEN.test(name) || /[\0\r\n]/.test(value))) {
    throw new Error('bad request header');
  }
  const socket = connect({ hostname: target.hostname, port: target.port },
    { secureTransport: target.tls ? 'on' : 'off', allowHalfOpen: false });
  let bytes: Bytes | null = null;
  const close = () => {
    bytes?.cancel();
    socket.close().catch(() => {});
  };
  try {
    const head = new TextEncoder().encode(
      `POST ${path} HTTP/1.1\r\n${headers.map(([name, value]) => `${name}: ${value}\r\n`).join('')}\r\n`);
    const request = new Uint8Array(head.length + payload.length);
    request.set(head);
    request.set(payload, head.length);
    const writer = socket.writable.getWriter();
    await writer.write(request);
    writer.releaseLock();
    bytes = new Bytes(socket.readable.getReader());
    const status = /^HTTP\/1\.[01] (\d{3})(?: .*)?$/.exec(await bytes.line(MAX_HEAD));
    if (!status) throw new Error('bad status line');
    const code = Number(status[1]);
    if (code < 200 || code > 599) throw new Error('interim or unknown status');
    const received = await fields(bytes, MAX_HEAD - status[0].length - 2);
    const framed = framing(code, received);
    let settle!: (trailers: Headers | null) => void;
    const trailers = new Promise<Headers | null>(resolve => { settle = resolve; });
    return { status: code, headers: received, body: body(bytes, framed, settle, close), trailers };
  } catch (error) {
    close();
    throw error;
  }
}
