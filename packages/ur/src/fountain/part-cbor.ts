import { fail } from "../error.ts";

/** Wire-level fountain part fields (decouples CBOR coding from {@link Part}). */
export type PartFields = {
  sequence: number;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  data: Uint8Array;
};

/** Encode a part to deterministic fixed-schema CBOR. */
export function encodePart(part: PartFields): Uint8Array {
  const { data } = part;
  const out: number[] = [0x85];
  encodeU32(out, part.sequence);
  encodeU32(out, part.sequenceCount);
  encodeU32(out, part.messageLength);
  encodeU32(out, part.checksum);
  encodeBstr(out, data);
  return new Uint8Array(out);
}

/** Decode a part from CBOR with data-length and fragment-count caps. */
export function decodePart(
  bytes: Uint8Array,
  maxDataLen: number,
  maxFragmentCount: number,
): PartFields {
  const cur = { i: 0 };
  if (read(bytes, cur) !== 0x85) {
    fail("InvalidPartCbor");
  }
  const sequence = decodeU32(bytes, cur);
  const sequenceCount = decodeU32(bytes, cur);
  const messageLength = decodeU32(bytes, cur);
  const checksum = decodeU32(bytes, cur);
  const data = decodeBstr(bytes, cur, maxDataLen);
  if (cur.i !== bytes.length) {
    fail("InvalidPartCbor");
  }
  if (sequence === 0) {
    fail("InvalidSequence");
  }
  if (sequenceCount === 0 || messageLength === 0 || data.length === 0) {
    fail("EmptyPart");
  }
  if (sequenceCount > maxFragmentCount) {
    fail("ResourceLimit", { limit: "fragment_count" });
  }
  return { sequence, sequenceCount, messageLength, checksum, data };
}

function encodeU32(out: number[], v: number): void {
  if (v <= 23) {
    out.push(v);
  } else if (v <= 0xff) {
    out.push(0x18, v);
  } else if (v <= 0xffff) {
    out.push(0x19, (v >>> 8) & 0xff, v & 0xff);
  } else {
    out.push(0x1a, (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
}

function encodeBstr(out: number[], data: Uint8Array): void {
  const len = data.length;
  if (len <= 23) {
    out.push(0x40 | len);
  } else if (len <= 0xff) {
    out.push(0x58, len);
  } else if (len <= 0xffff) {
    out.push(0x59, (len >>> 8) & 0xff, len & 0xff);
  } else {
    out.push(0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
  }
  for (const b of data) {
    out.push(b);
  }
}

function decodeU32(bytes: Uint8Array, cur: { i: number }): number {
  const head = read(bytes, cur);
  const major = head >> 5;
  const ai = head & 0x1f;
  if (major !== 0) {
    fail("InvalidPartCbor");
  }
  if (ai <= 23) {
    return ai;
  }
  if (ai === 24) {
    const v = read(bytes, cur);
    if (v <= 23) {
      fail("InvalidPartCbor");
    }
    return v;
  }
  if (ai === 25) {
    const v = (read(bytes, cur) << 8) | read(bytes, cur);
    if (v <= 0xff) {
      fail("InvalidPartCbor");
    }
    return v;
  }
  if (ai === 26) {
    const v =
      ((read(bytes, cur) << 24) |
        (read(bytes, cur) << 16) |
        (read(bytes, cur) << 8) |
        read(bytes, cur)) >>>
      0;
    if (v <= 0xffff) {
      fail("InvalidPartCbor");
    }
    return v;
  }
  return fail("InvalidPartCbor");
}

function decodeBstr(bytes: Uint8Array, cur: { i: number }, maxDataLen: number): Uint8Array {
  const head = read(bytes, cur);
  const major = head >> 5;
  const ai = head & 0x1f;
  if (major !== 2) {
    fail("InvalidPartCbor");
  }
  let len: number;
  if (ai <= 23) {
    len = ai;
  } else if (ai === 24) {
    len = read(bytes, cur);
    if (len <= 23) {
      fail("InvalidPartCbor");
    }
  } else if (ai === 25) {
    len = (read(bytes, cur) << 8) | read(bytes, cur);
    if (len <= 0xff) {
      fail("InvalidPartCbor");
    }
  } else if (ai === 26) {
    len =
      ((read(bytes, cur) << 24) |
        (read(bytes, cur) << 16) |
        (read(bytes, cur) << 8) |
        read(bytes, cur)) >>>
      0;
    if (len <= 0xffff) {
      fail("InvalidPartCbor");
    }
  } else {
    fail("InvalidPartCbor");
  }
  if (len > maxDataLen) {
    fail("ResourceLimit", { limit: "fragment_data" });
  }
  if (cur.i + len > bytes.length) {
    fail("InvalidPartCbor");
  }
  const data = bytes.slice(cur.i, cur.i + len);
  cur.i += len;
  return data;
}

function read(bytes: Uint8Array, cur: { i: number }): number {
  const b = bytes[cur.i];
  if (b === undefined) {
    fail("InvalidPartCbor");
  }
  cur.i += 1;
  return b;
}
