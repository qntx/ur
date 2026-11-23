import { bytesToHex, decodeCbor, encodeCbor, hexToBytes } from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import {
  cryptoAccountCodec,
  cryptoCoinInfoCodec,
  cryptoHdKeyCodec,
  cryptoKeypathCodec,
  cryptoOutputCodec,
  cryptoPsbtCodec,
} from "../../src/registry/index.ts";
import { fromUr, toUr, Ur } from "../../src/typed/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";
import { parseUrType, UrDecoder, UrEncoder } from "../../src/ur/index.ts";
import type { DecodedUr } from "../../src/ur/index.ts";
import { vectorJson } from "../vectors.ts";

type WriterCase = {
  readonly name: string;
  readonly codec: string;
  readonly inputCborHex: string;
  readonly v1CborHex: string;
  readonly ur: string;
  readonly source: string;
};

type InvalidCase = {
  readonly name: string;
  readonly codec: string;
  readonly inputCborHex: string;
  readonly tsError: string;
};

const WRITERS = vectorJson<{ cases: ReadonlyArray<WriterCase> }>("registry/v1-writers.json").cases;
const INVALID = vectorJson<{ cases: ReadonlyArray<InvalidCase> }>(
  "registry/v1-encode-invalid.json",
).cases;

const CODECS: Record<string, UrCodec<unknown>> = {
  "crypto-psbt": cryptoPsbtCodec,
  "crypto-hdkey": cryptoHdKeyCodec,
  "crypto-keypath": cryptoKeypathCodec,
  "crypto-coin-info": cryptoCoinInfoCodec,
  "crypto-output": cryptoOutputCodec,
  "crypto-account": cryptoAccountCodec,
};

function mustCodec(name: string): UrCodec<unknown> {
  const codec = CODECS[name];
  if (codec === undefined) {
    throw new Error(`no codec for ${name}`);
  }
  return codec;
}

function take<T>(iter: IterableIterator<T>, n: number): T[] {
  const out: T[] = [];
  for (let i = 0; i < n; i += 1) {
    const next = iter.next();
    if (next.done === true) {
      break;
    }
    out.push(next.value);
  }
  return out;
}

function completed(decoder: UrDecoder): DecodedUr {
  const { state } = decoder;
  if (state.phase !== "complete") {
    throw new Error("UR decode did not complete");
  }
  return state.value;
}

test.each(WRITERS)("v1-writers $codec $name", (c) => {
  const codec = mustCodec(c.codec);
  const input = decodeCbor(hexToBytes(c.inputCborHex));
  const value = codec.decode(input);
  expect(bytesToHex(encodeCbor(codec.encode(value)))).toBe(c.v1CborHex);
  expect(toUr(value, codec).toString()).toBe(c.ur);
  // The emitted UR decodes back to the same v1 body.
  const back = fromUr(Ur.parse(c.ur), codec);
  expect(bytesToHex(encodeCbor(codec.encode(back)))).toBe(c.v1CborHex);
});

test.each(INVALID)("v1-encode-invalid $codec $name", (c) => {
  const codec = mustCodec(c.codec);
  let thrown: unknown;
  try {
    codec.decode(decodeCbor(hexToBytes(c.inputCborHex)));
  } catch (error) {
    thrown = error;
  }
  expect(thrown, `${c.name}: expected ${c.tsError}`).toBeDefined();
  expect((thrown as { code?: string }).code).toBe(c.tsError);
});

test("v1-writers crypto-psbt BIP-174 multi-part UR round trip", () => {
  const c = WRITERS.find((w) => w.name.startsWith("BIP-174"));
  expect(c).toBeDefined();
  const codec = cryptoPsbtCodec;
  const value = codec.decode(decodeCbor(hexToBytes(c!.inputCborHex)));
  const message = encodeCbor(codec.encode(value));
  expect(bytesToHex(message)).toBe(c!.v1CborHex);

  const encoder = new UrEncoder(parseUrType("crypto-psbt"), message, {
    maxFragmentLength: 100,
  });
  expect(encoder.fragmentCount).toBeGreaterThan(1);

  const decoder = new UrDecoder({ accept: [parseUrType("crypto-psbt")] });
  for (const part of take(encoder, encoder.fragmentCount * 4)) {
    const result = decoder.receive(part);
    expect(["rejected", "fatal"]).not.toContain(result.status);
  }
  const decoded = completed(decoder);
  expect(bytesToHex(decoded.message)).toBe(c!.v1CborHex);
  // The reassembled body is still a valid crypto-psbt, byte-identical.
  const rt = codec.decode(decodeCbor(decoded.message));
  expect(bytesToHex(encodeCbor(codec.encode(rt)))).toBe(c!.inputCborHex);
});
