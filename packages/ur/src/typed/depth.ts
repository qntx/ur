/**
 * Maximum CBOR nesting depth accepted when decoding serialized dCBOR. Every array, map, and tag
 * counts as one level, empty containers included: depths 0..=64 are accepted and 65 is
 * `ResourceLimit` with limit `cborDepth`.
 */
export const CBOR_MAX_DEPTH = 64;

// Remaining item counts of the open containers. Every slot below `depth` is written before it is
// read within one synchronous call, so the scratch is never observed across calls.
const OPEN = new Float64Array(CBOR_MAX_DEPTH);

/**
 * Whether `data` opens more than {@link CBOR_MAX_DEPTH} nested containers. Walks CBOR heads
 * iteratively, in the decoder's order, and stops at the end of the first item, the end of input, or
 * the first head the decoder rejects (reserved or indefinite additional info). Everything else is
 * left to the decoder, which never reads past the point where this walk stopped. Arguments above
 * 2^53 lose precision but stay larger than any input, so the outcome is unchanged.
 */
export function exceedsCborDepth(data: Uint8Array): boolean {
  let depth = 0;
  let pos = 0;
  for (;;) {
    const initial = data[pos];
    if (initial === undefined) {
      return false;
    }
    const major = initial >> 5;
    const info = initial & 0x1f;
    if (info > 27) {
      return false;
    }
    const argLength = info < 24 ? 0 : 1 << (info - 24);
    if (pos + 1 + argLength > data.length) {
      return false;
    }
    let arg = info < 24 ? info : 0;
    for (let i = 1; i <= argLength; i++) {
      arg = arg * 256 + (data[pos + i] ?? 0);
    }
    pos += 1 + argLength;
    if (major === 2 || major === 3) {
      if (arg > data.length - pos) {
        return false;
      }
      pos += arg;
    } else if (major >= 4 && major <= 6) {
      if (depth === CBOR_MAX_DEPTH) {
        return true;
      }
      const items = major === 4 ? arg : major === 5 ? arg * 2 : 1;
      if (items > 0) {
        OPEN[depth] = items;
        depth += 1;
        continue;
      }
    }
    for (;;) {
      if (depth === 0) {
        return false;
      }
      const remaining = (OPEN[depth - 1] ?? 0) - 1;
      if (remaining > 0) {
        OPEN[depth - 1] = remaining;
        break;
      }
      depth -= 1;
    }
  }
}
