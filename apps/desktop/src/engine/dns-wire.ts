/**
 * Just enough of the DNS wire format (RFC 1035) for Safe DNS: read the question
 * of a query, and build a refusal or an error reply to it. Answers from the
 * upstream resolver are passed through untouched.
 */

export interface Question {
  id: number;
  /** Lower case, without the trailing dot. */
  name: string;
  type: number;
  /** Byte offset just after the question section. */
  end: number;
}

export const TYPE = { A: 1, AAAA: 28, HTTPS: 65 } as const;

/** Reads the first question; null for anything malformed or not a standard query. */
export function parseQuery(message: Uint8Array): Question | null {
  if (message.length < 12) return null;
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  const id = view.getUint16(0);
  const flags = view.getUint16(2);
  const isResponse = flags & 0x8000;
  const opcode = (flags >> 11) & 0xf;
  if (isResponse || opcode !== 0 || view.getUint16(4) < 1) return null;
  const labels: string[] = [];
  let offset = 12;
  for (let guard = 0; guard < 128; guard++) {
    if (offset >= message.length) return null;
    const length = message[offset]!;
    if (length === 0) {
      offset += 1;
      break;
    }
    // Compression pointers never appear in a query's first name.
    if (length > 63 || offset + 1 + length > message.length) return null;
    labels.push(new TextDecoder().decode(message.subarray(offset + 1, offset + 1 + length)));
    offset += 1 + length;
  }
  if (offset + 4 > message.length) return null;
  const name = labels.join(".").toLowerCase();
  if (name.length > 253) return null;
  return { id, name, type: view.getUint16(offset), end: offset + 4 };
}

/**
 * A reply to `query` with just its question and the given response code:
 * 3 (NXDOMAIN) to refuse a blocked domain, 2 (SERVFAIL) when nothing answered.
 */
export function replyWithCode(query: Uint8Array, question: Question, rcode: 2 | 3): Uint8Array {
  const reply = new Uint8Array(question.end);
  reply.set(query.subarray(0, question.end));
  const view = new DataView(reply.buffer);
  const flags = view.getUint16(2);
  // QR=1, keep opcode and RD, RA=1, rcode.
  view.setUint16(2, 0x8000 | (flags & 0x7900) | 0x0080 | rcode);
  view.setUint16(4, 1); // QDCOUNT
  view.setUint16(6, 0); // ANCOUNT
  view.setUint16(8, 0); // NSCOUNT
  view.setUint16(10, 0); // ARCOUNT
  return reply;
}

/** Builds a query (used by tests and the self-check). */
export function buildQuery(id: number, name: string, type: number): Uint8Array {
  const parts = name.split(".").filter(Boolean);
  const size = 12 + parts.reduce((n, p) => n + 1 + p.length, 0) + 1 + 4;
  const message = new Uint8Array(size);
  const view = new DataView(message.buffer);
  view.setUint16(0, id);
  view.setUint16(2, 0x0100); // RD
  view.setUint16(4, 1);
  let offset = 12;
  for (const part of parts) {
    message[offset] = part.length;
    message.set(new TextEncoder().encode(part), offset + 1);
    offset += 1 + part.length;
  }
  message[offset] = 0;
  view.setUint16(offset + 1, type);
  view.setUint16(offset + 3, 1); // IN
  return message;
}

export function responseCode(message: Uint8Array): number {
  return message.length >= 4 ? message[3]! & 0x0f : -1;
}

/** Copies the query id into an upstream answer (DoH answers use id 0). */
export function withId(message: Uint8Array, id: number): Uint8Array {
  const copy = new Uint8Array(message);
  new DataView(copy.buffer).setUint16(0, id);
  return copy;
}
