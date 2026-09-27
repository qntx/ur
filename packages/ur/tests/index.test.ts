import { expect, test } from "vite-plus/test";

import { encode, decode, UrType } from "../src/index.ts";

test("public api single-part roundtrip", () => {
  const data = new TextEncoder().encode("hello ur");
  const ur = encode(data, UrType.bytes());
  expect(ur.startsWith("ur:bytes/")).toBe(true);
  const { kind, payload } = decode(ur);
  expect(kind).toBe("single");
  expect(new TextDecoder().decode(payload)).toBe("hello ur");
});
