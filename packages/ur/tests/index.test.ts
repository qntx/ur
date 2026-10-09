import { expect, test } from "vite-plus/test";

import { encodeUr, parseUr, parseUrType } from "../src/index.ts";
import type { ParsedUr } from "../src/index.ts";

function parsedMessage(parsed: ParsedUr): Uint8Array {
  if (parsed.kind !== "single") {
    throw new Error(`expected single, got ${parsed.kind}`);
  }
  return parsed.message;
}

test("public api single-part roundtrip", () => {
  const data = new TextEncoder().encode("hello ur");
  const ur = encodeUr(parseUrType("bytes"), data);
  expect(ur.startsWith("ur:bytes/")).toBe(true);
  expect(new TextDecoder().decode(parsedMessage(parseUr(ur)))).toBe("hello ur");
});
