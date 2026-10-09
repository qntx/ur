import { cbor, cborEquals } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { UrError } from "../src/error.ts";
import type { ReceiveResult } from "../src/fountain/index.ts";
import { Ur } from "../src/typed/ur.ts";
import type { DecodedUr } from "../src/ur/index.ts";
import { Encoder, UrDecoder, UrType } from "../src/ur/index.ts";

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

function frameError(result: ReceiveResult): UrError | undefined {
  return "error" in result ? result.error : undefined;
}

function completedUr(decoder: UrDecoder): Ur {
  return Ur.fromDecoded(completedDecoded(decoder));
}

function completedDecoded(decoder: UrDecoder): DecodedUr {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.value;
}

function failedError(decoder: UrDecoder): UrError {
  const { state } = decoder;
  if (state.phase !== "failed") {
    throw new Error(`decoder ${state.phase}`);
  }
  return state.error;
}

function feedUr(decoder: UrDecoder, text: string): "accepted" | "duplicate" {
  const result = decoder.receive(text);
  if (result.status === "rejected" || result.status === "fatal") {
    throw result.error;
  }
  return result.status;
}

function largeTestUr(): Ur {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = i & 0xff;
  }
  return Ur.create("test", bytes);
}

test("K==1 emits single-part", () => {
  const ur = Ur.create("test", cbor([1, 2, 3]));
  const encoder = ur.encoder({ maxFragmentLength: 64 });
  expect(encoder.isSinglePart).toBe(true);
  expect(encoder.fragmentCount).toBe(1);
  const part = encoder.nextPart();
  expect(part).not.toContain("/1-1/");
  expect(part).toBe("ur:test/lsadaoaxjygonesw");
});

test("drop-odd-parts roundtrip same Cbor", () => {
  const ur = largeTestUr();
  const encoder = ur.encoder({ maxFragmentLength: 30 });
  expect(encoder.isSinglePart).toBe(false);
  const decoder = new UrDecoder();
  while (decoder.state.phase !== "complete") {
    feedUr(decoder, encoder.nextPart());
    encoder.nextPart();
  }
  const recovered = completedUr(decoder);
  expect(cborEquals(recovered.cbor, ur.cbor)).toBe(true);
  expect(recovered.type.equals(ur.type)).toBe(true);
});

test("accept mismatch is UnexpectedType and nonfatal", () => {
  const ur = Ur.create("alpha", cbor([1, 2, 3]));
  const encoder = ur.encoder({ maxFragmentLength: 64 });
  const decoder = new UrDecoder({ accept: [UrType.parse("beta")] });
  const result = decoder.receive(encoder.nextPart());
  expect(result.status).toBe("rejected");
  expect(frameError(result)?.info).toStrictEqual({
    code: "UnexpectedType",
    expected: [UrType.parse("beta")],
    found: UrType.parse("alpha"),
  });
  expect(decoder.state.phase).toBe("empty");
});

test("maxUriLength fails on a longer URI", () => {
  const ur = Ur.create("test", cbor([1, 2, 3]));
  const part = ur.encoder({ maxFragmentLength: 64 }).nextPart();
  const decoder = new UrDecoder({ limits: { maxUriLength: 8 } });
  expect(part.length).toBeGreaterThan(8);
  const result = decoder.receive(part);
  expect(result.status).toBe("fatal");
  expect(frameError(result)?.info).toStrictEqual({
    code: "ResourceLimit",
    limit: "uriLength",
  });
  expect(decoder.state.phase).toBe("failed");
  expect(failedError(decoder).info).toStrictEqual({
    code: "ResourceLimit",
    limit: "uriLength",
  });
});

test("non-dCBOR complete payload is CborDecode", () => {
  const encoder = Encoder.bytes(new TextEncoder().encode("hello"), 64);
  const decoder = new UrDecoder();
  feedUr(decoder, encoder.nextPart());
  const decoded = completedDecoded(decoder);
  expect(errorOf(() => Ur.fromDecoded(decoded)).code).toBe("CborDecode");
});

test("uppercase fountain parts roundtrip", () => {
  const ur = largeTestUr();
  const encoder = ur.encoder({ maxFragmentLength: 30 });
  expect(encoder.isSinglePart).toBe(false);
  const decoder = new UrDecoder();
  while (decoder.state.phase !== "complete") {
    feedUr(decoder, encoder.nextPart().toUpperCase());
  }
  const recovered = completedUr(decoder);
  expect(cborEquals(recovered.cbor, ur.cbor)).toBe(true);
  expect(recovered.type.equals(ur.type)).toBe(true);
});
