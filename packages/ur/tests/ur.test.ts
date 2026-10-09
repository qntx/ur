import { expect, test } from "vite-plus/test";

import { UrError } from "../src/error.ts";
import type { ReceiveResult } from "../src/fountain/index.ts";
import {
  UrDecoder,
  UrEncoder,
  encodeUr,
  isUrType,
  parseUr,
  parseUrType,
  toQrString,
} from "../src/ur/index.ts";
import type { ParsedUr } from "../src/ur/index.ts";
import { makeMessage } from "./message.ts";

function frameError(result: ReceiveResult): UrError | undefined {
  return "error" in result ? result.error : undefined;
}

function feedUr(decoder: UrDecoder, text: string): "accepted" | "duplicate" {
  const result = decoder.receive(text);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
  return result.status;
}

function decodedMessage(decoder: UrDecoder): Uint8Array {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value.message;
}

function parsedMessage(parsed: ParsedUr): Uint8Array {
  if (parsed.kind !== "single") {
    throw new Error(`expected single, got ${parsed.kind}`);
  }
  return parsed.message;
}

function nextUr(encoder: UrEncoder): string {
  const { value, done } = encoder.next();
  if (done === true || value === undefined) {
    throw new Error("ur encoder exhausted");
  }
  return value;
}

function bytesEncoder(data: Uint8Array, maxFragmentLength: number): UrEncoder {
  return new UrEncoder(parseUrType("bytes"), data, { maxFragmentLength });
}

function errorOf(fn: () => void): UrError {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error;
    }
    throw error;
  }
  throw new Error("expected UrError");
}

/** CBOR bstr wrapping (major type 2) — matches ur-rs test helper for message URs. */
function cborBstr(message: Uint8Array): Uint8Array {
  const len = message.length;
  let header: number[];
  if (len <= 23) {
    header = [0x40 | len];
  } else if (len <= 0xff) {
    header = [0x58, len];
  } else if (len <= 0xffff) {
    header = [0x59, (len >>> 8) & 0xff, len & 0xff];
  } else {
    header = [0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
  }
  const out = new Uint8Array(header.length + len);
  out.set(header);
  out.set(message, header.length);
  return out;
}

function makeMessageUr(length: number, seed: string): Uint8Array {
  return cborBstr(makeMessage(seed, length));
}

test("single part ur", () => {
  const ur = makeMessageUr(50, "Wolf");
  const encoded = encodeUr(parseUrType("bytes"), ur);
  const expected =
    "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
  expect(encoded).toBe(expected);
  const parsed = parseUr(encoded);
  expect(parsed.kind).toBe("single");
  expect(parsedMessage(parsed)).toStrictEqual(ur);
});

test("ur encoder first three parts (smoke; full 20 in interop-ur-rs)", () => {
  const ur = makeMessageUr(256, "Wolf");
  const encoder = bytesEncoder(ur, 30);
  const expected = [
    "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
    "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
    "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
  ];
  expect(encoder.fragmentCount).toBe(9);
  for (const part of expected) {
    expect(nextUr(encoder)).toBe(part);
  }
});

test("multipart ur", () => {
  const ur = makeMessageUr(32767, "Wolf");
  const encoder = bytesEncoder(ur, 1000);
  const decoder = new UrDecoder();
  while (decoder.state.phase !== "complete") {
    expect(["empty", "collecting"]).toContain(decoder.state.phase);
    feedUr(decoder, nextUr(encoder));
  }
  expect(decodedMessage(decoder)).toStrictEqual(ur);
});

test("data encode", () => {
  expect(encodeUr(parseUrType("bytes"), new TextEncoder().encode("data"))).toBe(
    "ur:bytes/iehsjyhspmwfwfia",
  );
});

test("case fold", () => {
  const lower = encodeUr(parseUrType("bytes"), new TextEncoder().encode("data"));
  const upper = toQrString(lower);
  expect(parseUr(upper)).toStrictEqual(parseUr(lower));
});

test("type stickiness", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const encA = new UrEncoder(parseUrType("alpha"), data, { maxFragmentLength: 10 });
  const encB = new UrEncoder(parseUrType("beta"), data, { maxFragmentLength: 10 });
  const decoder = new UrDecoder();
  feedUr(decoder, nextUr(encA));
  const result = decoder.receive(nextUr(encB));
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("UnexpectedType");
});

test("invalid scheme", () => {
  expect(() => parseUr("uhr:bytes/aeadaolazmjendeoti")).toThrow(UrError);
});

test("invalid maxFragmentLength through UrEncoder", () => {
  const data = new TextEncoder().encode("data");
  const cases = [Number.NaN, -1, 0, 0.5, 1.5, Number.POSITIVE_INFINITY];
  for (const len of cases) {
    expect(errorOf(() => bytesEncoder(data, len)).code).toBe("InvalidFragmentLength");
  }
});

test("custom encoder", () => {
  const data = new TextEncoder().encode("Ten chars!");
  const encoder = new UrEncoder(parseUrType("my-scheme"), data, {
    maxFragmentLength: 5,
    minFragmentLength: 5,
  });
  expect(nextUr(encoder)).toBe("ur:my-scheme/1-2/lpadaobkcywkwmhfwnfeghihjtcxiansvomopr");
});

test("test_single_part_receive_completes", () => {
  const decoder = new UrDecoder();
  expect(feedUr(decoder, "ur:bytes/iehsjyhspmwfwfia")).toBe("accepted");
  expect(decoder.state.phase).toBe("complete");
  expect(decoder.progress).toStrictEqual({
    fragmentCount: 1,
    rank: 1,
    recovered: 1,
    processed: 1,
    ratio: 1,
  });
  expect(decodedMessage(decoder)).toStrictEqual(new TextEncoder().encode("data"));
});

test("UrEncoder K==1 emits single-part", () => {
  const data = new TextEncoder().encode("hello");
  const encoder = bytesEncoder(data, 64);
  expect(encoder.isSinglePart).toBe(true);
  expect(encoder.fragmentCount).toBe(1);
  const part = nextUr(encoder);
  expect(part).not.toContain("/1-1/");
  expect(part).toBe(encodeUr(parseUrType("bytes"), data));
});

test("UrEncoder K==1 repeats the same single-part UR", () => {
  const data = new TextEncoder().encode("hello");
  const encoder = bytesEncoder(data, 64);
  expect(encoder.isComplete).toBe(false);
  const first = nextUr(encoder);
  expect(first).toBe(encodeUr(parseUrType("bytes"), data));
  expect(encoder.isSinglePart).toBe(true);
  expect(encoder.isComplete).toBe(true);
  const second = nextUr(encoder);
  expect(second).toBe(first);
  expect(encoder.isComplete).toBe(true);
});

test("multi after completed single is a terminal duplicate", () => {
  const decoder = new UrDecoder();
  feedUr(decoder, encodeUr(parseUrType("bytes"), new TextEncoder().encode("data")));
  const enc = bytesEncoder(new TextEncoder().encode("Ten chars!".repeat(5)), 10);
  expect(decoder.receive(nextUr(enc)).status).toBe("duplicate");
});

test("mix fountain then single", () => {
  const decoder = new UrDecoder();
  const enc = bytesEncoder(new TextEncoder().encode("Ten chars!".repeat(5)), 10);
  feedUr(decoder, nextUr(enc));
  const result = decoder.receive("ur:bytes/iehsjyhspmwfwfia");
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("InconsistentPart");
});

test("duplicate single-part ignored", () => {
  const first = new TextEncoder().encode("data");
  const second = new TextEncoder().encode("other");
  const decoder = new UrDecoder();
  feedUr(decoder, encodeUr(parseUrType("bytes"), first));
  expect(feedUr(decoder, encodeUr(parseUrType("bytes"), second))).toBe("duplicate");
  expect(decodedMessage(decoder)).toStrictEqual(first);
});

test("parseUr single-part round trip", () => {
  const parsed = parseUr(encodeUr(parseUrType("bytes"), new TextEncoder().encode("data")));
  expect(parsedMessage(parsed)).toStrictEqual(new TextEncoder().encode("data"));
});

test("parseUr identifies multi-part", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(8));
  const encoder = bytesEncoder(data, 10);
  const parsed = parseUr(nextUr(encoder));
  expect(parsed.kind).toBe("multi");
});

test("test_garbage_does_not_pin_type", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(6));
  const encoder = new UrEncoder(parseUrType("alpha"), data, { maxFragmentLength: 10 });
  const other = new UrEncoder(parseUrType("beta"), data, { maxFragmentLength: 10 });
  const decoder = new UrDecoder();
  const garbage = decoder.receive("ur:beta/1-2/zzzz");
  expect(garbage.status).toBe("rejected");
  expect(decoder.state.phase).toBe("empty");
  feedUr(decoder, nextUr(encoder));
  expect(decoder.state.phase).toBe("collecting");
  const wrong = decoder.receive(nextUr(other));
  expect(wrong.status).toBe("rejected");
  expect(frameError(wrong)?.code).toBe("UnexpectedType");
});

test("bc-ur example array", () => {
  const cbor = Uint8Array.from([0x83, 0x01, 0x02, 0x03]);
  const ur = encodeUr(parseUrType("test"), cbor);
  expect(ur).toBe("ur:test/lsadaoaxjygonesw");
  const parsed = parseUr(ur);
  expect(parsed.kind).toBe("single");
  expect(parsedMessage(parsed)).toStrictEqual(cbor);
});

test("parseUr shape", () => {
  const ur = encodeUr(parseUrType("bytes"), new TextEncoder().encode("data"));
  const parsed = parseUr(ur);
  expect(parsed.kind).toBe("single");
  expect(parsed.type).toBe("bytes");
});

test("empty single part", () => {
  const ur = encodeUr(parseUrType("bytes"), new Uint8Array());
  const parsed = parseUr(ur);
  expect(parsed.kind).toBe("single");
  expect(parsedMessage(parsed)).toStrictEqual(new Uint8Array());
});

test("parseUrType lowercases and validates", () => {
  expect(parseUrType("BYTES")).toBe("bytes");
  expect(parseUrType("crypto-request")).toBe("crypto-request");
  expect(errorOf(() => parseUrType("")).code).toBe("InvalidType");
  expect(errorOf(() => parseUrType("not_a_type")).code).toBe("InvalidType");
  expect(errorOf(() => parseUrType("a b")).code).toBe("InvalidType");
});

test("isUrType requires canonical lowercase", () => {
  expect(isUrType("bytes")).toBe(true);
  expect(isUrType("crypto-request-1")).toBe(true);
  expect(isUrType("BYTES")).toBe(false);
  expect(isUrType("")).toBe(false);
  expect(isUrType("not_a_type")).toBe(false);
});
