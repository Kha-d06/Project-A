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

export interface Answers {
  /** Every CNAME target in the answer section, lower case. */
  cnames: string[];
  /** A and AAAA addresses in the answer section. */
  addresses: string[];
}

const MAX_RECORDS = 64;

/** Reads a (possibly compressed) name at `offset`; returns it and where the record continues. */
function readName(message: Uint8Array, offset: number): { name: string; next: number } | null {
  const labels: string[] = [];
  let next = -1;
  let jumps = 0;
  let at = offset;
  for (;;) {
    if (at >= message.length) return null;
    const length = message[at]!;
    if (length === 0) {
      if (next < 0) next = at + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (at + 1 >= message.length || ++jumps > 16) return null; // pointer loops
      if (next < 0) next = at + 2;
      at = ((length & 0x3f) << 8) | message[at + 1]!;
      continue;
    }
    if (length > 63 || at + 1 + length > message.length) return null;
    labels.push(new TextDecoder().decode(message.subarray(at + 1, at + 1 + length)));
    at += 1 + length;
    if (labels.length > 127) return null;
  }
  return { name: labels.join(".").toLowerCase(), next };
}

function ipv6(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) parts.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
  return parts.join(":");
}

/** CNAME targets and addresses in an upstream answer; null if it can't be read safely. */
export function parseAnswers(message: Uint8Array): Answers | null {
  if (message.length < 12) return null;
  const view = new DataView(message.buffer, message.byteOffset, message.byteLength);
  const questions = view.getUint16(4);
  const answers = view.getUint16(6);
  if (questions > 4 || answers > MAX_RECORDS) return null;
  let offset = 12;
  for (let q = 0; q < questions; q++) {
    const name = readName(message, offset);
    if (!name || name.next + 4 > message.length) return null;
    offset = name.next + 4;
  }
  const out: Answers = { cnames: [], addresses: [] };
  for (let a = 0; a < answers; a++) {
    const name = readName(message, offset);
    if (!name || name.next + 10 > message.length) return null;
    const type = view.getUint16(name.next);
    const length = view.getUint16(name.next + 8);
    const data = name.next + 10;
    if (data + length > message.length) return null;
    if (type === 5) {
      const target = readName(message, data);
      if (!target) return null;
      out.cnames.push(target.name);
    } else if (type === TYPE.A && length === 4) {
      out.addresses.push(Array.from(message.subarray(data, data + 4)).join("."));
    } else if (type === TYPE.AAAA && length === 16) {
      out.addresses.push(ipv6(message.subarray(data, data + 16)));
    }
    offset = data + length;
  }
  return out;
}

/** Private, loopback, link-local, CGNAT or unspecified: never a public site's address. */
export function isPrivateAddress(address: string): boolean {
  if (address.includes(":")) {
    const first = Number.parseInt(address.split(":")[0] || "0", 16);
    const normal = address.toLowerCase();
    if (normal === "0:0:0:0:0:0:0:1" || normal === "0:0:0:0:0:0:0:0") return true;
    if ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80) return true; // fc00::/7, fe80::/10
    // ::ffff:a.b.c.d (IPv4-mapped)
    const parts = normal.split(":");
    if (parts.slice(0, 5).every((p) => p === "0") && parts[5] === "ffff") {
      const hi = Number.parseInt(parts[6]!, 16);
      const lo = Number.parseInt(parts[7]!, 16);
      return isPrivateAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return false;
  }
  const [a = -1, b = -1] = address.split(".").map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}
