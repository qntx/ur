import { expect, test } from "vite-plus/test";

import { UrError } from "../src/error.ts";
import type { ReceiveResult } from "../src/fountain/index.ts";
import {
  Encoder,
  UrDecoder,
  UrType,
  decode,
  decodeMessage,
  encode,
  parse,
  toQrString,
} from "../src/ur/index.ts";
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
  const encoded = encode(ur, UrType.bytes());
  const expected =
    "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
  expect(encoded).toBe(expected);
  const decoded = decode(encoded);
  expect(decoded.kind).toBe("single");
  expect(decoded.payload).toStrictEqual(ur);
});

test("ur encoder first three parts (smoke; full 20 in interop-ur-rs)", () => {
  const ur = makeMessageUr(256, "Wolf");
  const encoder = Encoder.bytes(ur, 30);
  const expected = [
    "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
    "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
    "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
  ];
  expect(encoder.fragmentCount).toBe(9);
  for (let index = 0; index < expected.length; index++) {
    expect(encoder.currentIndex).toBe(index);
    expect(encoder.nextPart()).toBe(expected[index]);
  }
});

test("multipart ur", () => {
  const ur = makeMessageUr(32767, "Wolf");
  const encoder = Encoder.bytes(ur, 1000);
  const decoder = new UrDecoder();
  while (decoder.state.phase !== "complete") {
    expect(["empty", "collecting"]).toContain(decoder.state.phase);
    feedUr(decoder, encoder.nextPart());
  }
  expect(decodedMessage(decoder)).toStrictEqual(ur);
});

test("data encode", () => {
  expect(encode(new TextEncoder().encode("data"), UrType.bytes())).toBe(
    "ur:bytes/iehsjyhspmwfwfia",
  );
});

test("case fold", () => {
  const lower = encode(new TextEncoder().encode("data"), UrType.bytes());
  const upper = toQrString(lower);
  expect(decode(upper)).toStrictEqual(decode(lower));
});

test("type stickiness", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(5));
  const encA = Encoder.create(data, 10, UrType.parse("alpha"));
  const encB = Encoder.create(data, 10, UrType.parse("beta"));
  const decoder = new UrDecoder();
  feedUr(decoder, encA.nextPart());
  const result = decoder.receive(encB.nextPart());
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("UnexpectedType");
});

test("invalid scheme", () => {
  expect(() => decode("uhr:bytes/aeadaolazmjendeoti")).toThrow(UrError);
});

test("invalid maxFragmentLength through Encoder.bytes", () => {
  const data = new TextEncoder().encode("data");
  const cases = [Number.NaN, -1, 0, 0.5, 1.5, Number.POSITIVE_INFINITY];
  for (const len of cases) {
    expect(errorOf(() => Encoder.bytes(data, len)).code).toBe("InvalidFragmentLength");
  }
});

test("custom encoder", () => {
  const data = new TextEncoder().encode("Ten chars!");
  const encoder = Encoder.create(data, 5, UrType.parse("my-scheme"), {
    minFragmentLength: 5,
  });
  expect(encoder.nextPart()).toBe("ur:my-scheme/1-2/lpadaobkcywkwmhfwnfeghihjtcxiansvomopr");
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

test("Encoder K==1 emits single-part", () => {
  const data = new TextEncoder().encode("hello");
  const encoder = Encoder.bytes(data, 64);
  expect(encoder.isSinglePart).toBe(true);
  expect(encoder.fragmentCount).toBe(1);
  const part = encoder.nextPart();
  expect(part).not.toContain("/1-1/");
  expect(part).toBe(encode(data, UrType.bytes()));
});

test("Encoder K==1 idempotent", () => {
  const data = new TextEncoder().encode("hello");
  const encoder = Encoder.bytes(data, 64);
  expect(encoder.complete).toBe(false);
  expect(encoder.currentIndex).toBe(0);
  const first = encoder.nextPart();
  expect(first).toBe(encode(data, UrType.bytes()));
  expect(encoder.currentIndex).toBe(1);
  expect(encoder.isSinglePart).toBe(true);
  expect(encoder.complete).toBe(true);
  const second = encoder.nextPart();
  expect(second).toBe(first);
  expect(encoder.currentIndex).toBe(1);
  expect(encoder.complete).toBe(true);
});

test("multi after completed single is a terminal duplicate", () => {
  const decoder = new UrDecoder();
  feedUr(decoder, encode(new TextEncoder().encode("data"), UrType.bytes()));
  const enc = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(5)), 10);
  expect(decoder.receive(enc.nextPart()).status).toBe("duplicate");
});

test("mix fountain then single", () => {
  const decoder = new UrDecoder();
  const enc = Encoder.bytes(new TextEncoder().encode("Ten chars!".repeat(5)), 10);
  feedUr(decoder, enc.nextPart());
  const result = decoder.receive("ur:bytes/iehsjyhspmwfwfia");
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.code).toBe("InconsistentPart");
});

test("duplicate single-part ignored", () => {
  const first = new TextEncoder().encode("data");
  const second = new TextEncoder().encode("other");
  const decoder = new UrDecoder();
  feedUr(decoder, encode(first, UrType.bytes()));
  expect(feedUr(decoder, encode(second, UrType.bytes()))).toBe("duplicate");
  expect(decodedMessage(decoder)).toStrictEqual(first);
});

test("decodeMessage success", () => {
  expect(decodeMessage(encode(new TextEncoder().encode("data"), UrType.bytes()))).toStrictEqual(
    new TextEncoder().encode("data"),
  );
});

test("test_decode_message_rejects_multipart", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(8));
  const encoder = Encoder.bytes(data, 10);
  const part = encoder.nextPart();
  expect(errorOf(() => decodeMessage(part)).code).toBe("NotSinglePart");
});

test("test_garbage_does_not_pin_type", () => {
  const data = new TextEncoder().encode("Ten chars!".repeat(6));
  const encoder = Encoder.create(data, 10, UrType.parse("alpha"));
  const other = Encoder.create(data, 10, UrType.parse("beta"));
  const decoder = new UrDecoder();
  const garbage = decoder.receive("ur:beta/1-2/zzzz");
  expect(garbage.status).toBe("rejected");
  expect(decoder.state.phase).toBe("empty");
  feedUr(decoder, encoder.nextPart());
  expect(decoder.state.phase).toBe("collecting");
  const wrong = decoder.receive(other.nextPart());
  expect(wrong.status).toBe("rejected");
  expect(frameError(wrong)?.code).toBe("UnexpectedType");
});

test("bc-ur example array", () => {
  const cbor = Uint8Array.from([0x83, 0x01, 0x02, 0x03]);
  const ur = encode(cbor, UrType.parse("test"));
  expect(ur).toBe("ur:test/lsadaoaxjygonesw");
  const { kind, payload } = decode(ur);
  expect(kind).toBe("single");
  expect(payload).toStrictEqual(cbor);
});

test("parse", () => {
  const ur = encode(new TextEncoder().encode("data"), UrType.bytes());
  const parsed = parse(ur);
  expect(parsed.kind).toBe("single");
  expect(parsed.type.value).toBe("bytes");
  expect(parsed.indices).toBeUndefined();
});

test("empty single part", () => {
  const ur = encode(new Uint8Array(), UrType.bytes());
  const { kind, payload } = decode(ur);
  expect(kind).toBe("single");
  expect(payload).toStrictEqual(new Uint8Array());
});
