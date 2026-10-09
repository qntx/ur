import { checksum } from "../consensus/crc32.ts";
import { BYTEMOJIS, MINIMALS, WORDS } from "../constants.ts";
import { fail } from "../error.ts";

/** Bytewords encoding styles (BCR-2020-012). */
export type BytewordsStyle = "standard" | "uri" | "minimal";

export { BYTEMOJIS, MINIMALS, WORDS } from "../constants.ts";

const wordByToken = new Map<string, number>();
for (const [i, word] of WORDS.entries()) {
  wordByToken.set(word, i);
}
for (const [i, minimal] of MINIMALS.entries()) {
  wordByToken.set(minimal, i);
}

// Byte values are 0..255 and all tables have exactly 256 entries.
function wordAt(table: ReadonlyArray<string>, byte: number): string {
  const word = table[byte];
  if (word === undefined) {
    throw new Error("byteword index out of range");
  }
  return word;
}

function checksumBytes(data: Uint8Array): Uint8Array {
  const crc = checksum(data);
  return new Uint8Array([(crc >>> 24) & 0xff, (crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff]);
}

function encodeWords(data: Uint8Array, style: BytewordsStyle): string {
  const parts: string[] = [];
  const table = style === "minimal" ? MINIMALS : WORDS;
  for (const b of data) {
    parts.push(wordAt(table, b));
  }
  const seps: Record<BytewordsStyle, string> = { standard: " ", uri: "-", minimal: "" };
  return parts.join(seps[style]);
}

/** Encode `data` with trailing CRC-32 as bytewords. Empty data is allowed. */
export function encodeBytewords(data: Uint8Array, style: BytewordsStyle): string {
  const withCrc = new Uint8Array(data.length + 4);
  withCrc.set(data);
  withCrc.set(checksumBytes(data), data.length);
  return encodeWords(withCrc, style);
}

/** The four checksum words of `data` alone (URKit `checksumWords` semantics). */
export function bytewordsChecksum(data: Uint8Array, style: BytewordsStyle): string {
  return encodeWords(checksumBytes(data), style);
}

/** Encoded length of `length` bytes (without a checksum) for `style`. */
export function bytewordsEncodedLength(length: number, style: BytewordsStyle): number {
  if (length <= 0) {
    return 0;
  }
  return style === "minimal" ? length * 2 : length * 5 - 1;
}

/** Four-word standard-style identifier of a 4-byte digest (BCR-2020-012). */
export function bytewordsIdentifier(data: Uint8Array): string {
  if (data.length !== 4) {
    throw new TypeError("bytewords identifier requires exactly 4 bytes");
  }
  return encodeWords(data, "standard");
}

/** Four-emoji identifier of a 4-byte digest (BCR-2024-008). */
export function bytemojiIdentifier(data: Uint8Array): string {
  if (data.length !== 4) {
    throw new TypeError("bytemoji identifier requires exactly 4 bytes");
  }
  const emojis: string[] = [];
  for (const b of data) {
    emojis.push(wordAt(BYTEMOJIS, b));
  }
  return emojis.join(" ");
}

/** Decode bytewords and verify CRC-32. Case-insensitive. */
export function decodeBytewords(text: string, style: BytewordsStyle): Uint8Array {
  for (const ch of text) {
    if ((ch.codePointAt(0) ?? 0) > 0x7f) {
      fail("NonAscii");
    }
  }
  const lowered = text.toLowerCase();
  if (style === "minimal") {
    return decodeMinimal(lowered);
  }
  const sep = style === "standard" ? " " : "-";
  const parts = lowered.length === 0 ? [] : lowered.split(sep);
  return decodeParts(parts, false);
}

function decodeMinimal(encoded: string): Uint8Array {
  if (encoded.length % 2 !== 0) {
    fail("InvalidBytewordsLength");
  }
  const parts: string[] = [];
  for (let i = 0; i < encoded.length; i += 2) {
    parts.push(encoded.slice(i, i + 2));
  }
  return decodeParts(parts, true);
}

function decodeParts(parts: string[], minimal: boolean): Uint8Array {
  const data = new Uint8Array(parts.length);
  for (const [i, part] of parts.entries()) {
    const expectedLen = minimal ? 2 : 4;
    if (part.length !== expectedLen) {
      fail("InvalidWord");
    }
    const byte = wordByToken.get(part);
    if (byte === undefined) {
      fail("InvalidWord");
    }
    // Confirm table entry matches (guards hash-style collisions).
    const expected = wordAt(minimal ? MINIMALS : WORDS, byte);
    if (part !== expected) {
      fail("InvalidWord");
    }
    data[i] = byte;
  }
  return stripChecksum(data);
}

function stripChecksum(data: Uint8Array): Uint8Array {
  if (data.length < 4) {
    fail("InvalidBytewordsChecksum");
  }
  const split = data.length - 4;
  const payload = data.subarray(0, split);
  const expected = checksum(payload);
  const got = new DataView(data.buffer, data.byteOffset + split, 4).getUint32(0);
  if (got !== expected) {
    fail("InvalidBytewordsChecksum");
  }
  return new Uint8Array(payload);
}

/** Canonicalize a 2–4 letter token to the full 4-letter lowercase byteword. */
export function canonicalizeByteword(token: string): string | undefined {
  for (const ch of token) {
    if ((ch.codePointAt(0) ?? 0) > 0x7f) {
      return undefined;
    }
  }
  const lower = token.toLowerCase();
  if (lower.length === 4) {
    const b = wordByToken.get(lower);
    return b === undefined ? undefined : WORDS[b];
  }
  if (lower.length === 2) {
    const b = wordByToken.get(lower);
    return b === undefined ? undefined : WORDS[b];
  }
  if (lower.length === 3) {
    let found: string | undefined;
    for (const word of WORDS) {
      if (word.slice(0, 3) === lower || word.slice(1, 4) === lower) {
        if (found !== undefined) {
          return undefined;
        }
        found = word;
      }
    }
    return found;
  }
  return undefined;
}
