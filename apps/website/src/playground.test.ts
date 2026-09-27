import { expect, test } from "vite-plus/test";

import {
  PSBT_MAX_FRAGMENT_LENGTH,
  decodePsbt,
  decodeSeed,
  encodePsbtParts,
  encodeSeed,
  parseHex,
  toHex,
} from "./playground.ts";

test("16-byte seed encode/decode roundtrip", () => {
  const payload = parseHex("00112233445566778899aabbccddeeff");
  expect(payload).toHaveLength(16);
  const ur = encodeSeed(payload);
  expect(ur.startsWith("ur:seed/")).toBe(true);
  expect(toHex(decodeSeed(ur))).toBe("00112233445566778899aabbccddeeff");
});

test("psbt encodes multipart parts at maxFragmentLength 50", () => {
  const bytes = new Uint8Array(200);
  bytes.set([0x70, 0x73, 0x62, 0x74, 0xff]);
  const parts = encodePsbtParts(bytes);
  expect(PSBT_MAX_FRAGMENT_LENGTH).toBe(50);
  expect(parts.length).toBeGreaterThan(1);
  expect(parts.every((part) => part.startsWith("ur:psbt/"))).toBe(true);
  expect(toHex(decodePsbt(parts.join("\n")))).toBe(toHex(bytes));
});
