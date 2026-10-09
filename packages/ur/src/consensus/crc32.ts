import { fail } from "../error.ts";

/** CRC-32 ISO-HDLC (polynomial 0xedb88320), matching bcur / ur-rs. */

const TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

/** CRC-32 ISO-HDLC checksum of `data`. */
export function checksum(data: Uint8Array): number {
  let crc = 0xff_ff_ff_ff;
  for (const b of data) {
    crc = (TABLE[(crc ^ b) & 0xff] ?? fail("Internal")) ^ (crc >>> 8);
  }
  return (crc ^ 0xff_ff_ff_ff) >>> 0;
}
