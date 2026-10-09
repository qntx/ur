import {
  UrDecoder,
  UrEncoder,
  decodeBytewords,
  encodeBytewords,
  encodeUr,
  parseUr,
  parseUrType,
} from "../../src/index.ts";
import { Ur, fromUr, psbtCodec, seedCodec, toUr } from "../../src/registry/index.ts";

/**
 * Hermes smoke test: bundled to a single classic script and run on the Hermes V1 CLI that React
 * Native ships. Hard asserts only; entry.ts prints `HERMES_SMOKE_OK` after every check settles.
 *
 * The OK line is the pass contract: Hermes exits 0 even for unhandled async errors, so runners must
 * assert the marker appears in stdout.
 */

function assert(cond: boolean, name: string): asserts cond {
  if (!cond) {
    throw new Error(`smoke: ${name}`);
  }
}
function eq<T>(got: T, want: T, name: string): void {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(`smoke: ${name}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function must<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("smoke: expected defined value");
  }
  return value;
}

function nextPart(encoder: UrEncoder): string {
  const { value, done } = encoder.next();
  if (done === true) {
    throw new Error("smoke: encoder exhausted");
  }
  return value;
}

export function main(): void {
  // Bytewords: fixed vector plus a round trip.
  eq(encodeBytewords(new Uint8Array([0]), "minimal"), "aetdaowslg", "bytewords minimal vector");
  const payload = hexToBytes("baadbeefcafe00112233445566778899");
  eq(
    bytesToHex(decodeBytewords(encodeBytewords(payload, "minimal"), "minimal")),
    bytesToHex(payload),
    "bytewords round trip",
  );

  // Single-part UR encode/decode.
  const uri = encodeUr(parseUrType("bytes"), payload);
  assert(uri.startsWith("ur:bytes/"), "single-part prefix");
  const parsed = parseUr(uri);
  eq(parsed.kind, "single", "single-part kind");
  eq(
    bytesToHex(parsed.kind === "single" ? parsed.message : new Uint8Array()),
    bytesToHex(payload),
    "single-part round trip",
  );

  // Multi-part root transport: UrEncoder -> UrDecoder over a few hundred bytes.
  const message = new Uint8Array(300);
  for (let i = 0; i < message.length; i++) {
    message[i] = i & 0xff;
  }
  const encoder = new UrEncoder(parseUrType("bytes"), message, { maxFragmentLength: 30 });
  assert(!encoder.isSinglePart, "multipart encoder");
  assert(encoder.fragmentCount > 1, "multipart fragment count");
  const decoder = new UrDecoder();
  for (let i = 0; i < 1000 && decoder.state.phase !== "complete"; i++) {
    const result = decoder.receive(nextPart(encoder));
    assert(result.status === "accepted" || result.status === "duplicate", "multipart frame ok");
  }
  assert(decoder.state.phase === "complete", "multipart decoder completes");
  const decoded = decoder.state.phase === "complete" ? decoder.state.value : undefined;
  eq(bytesToHex(must(decoded).message), bytesToHex(message), "multipart round trip");

  // Registry path: ur:seed single-part round trip through the typed codec API.
  // The `name` field forces a dCBOR text-string decode through the TextDecoder
  // shim (dcbor decodes text with `{ fatal: true }`).
  const seedPayload = hexToBytes("000102030405060708090a0b0c0d0e0f");
  const seedUri = toUr({ payload: seedPayload, name: "hermes" }, seedCodec).toString();
  assert(seedUri.startsWith("ur:seed/"), "seed ur type");
  const seed = fromUr(Ur.parse(seedUri), seedCodec);
  eq(bytesToHex(seed.payload), bytesToHex(seedPayload), "seed round trip");
  eq(seed.name, "hermes", "seed name text decode");

  // Registry path: ur:psbt multi-part round trip (magic-prefixed bytes).
  const psbtBytes = new Uint8Array(200);
  psbtBytes.set([0x70, 0x73, 0x62, 0x74, 0xff]);
  for (let i = 5; i < psbtBytes.length; i++) {
    psbtBytes[i] = (i * 7) & 0xff;
  }
  const psbtEncoder = toUr({ bytes: psbtBytes }, psbtCodec).encoder({ maxFragmentLength: 30 });
  assert(!psbtEncoder.isSinglePart, "psbt multipart encoder");
  const psbtDecoder = new UrDecoder();
  for (let i = 0; i < 1000 && psbtDecoder.state.phase !== "complete"; i++) {
    const result = psbtDecoder.receive(nextPart(psbtEncoder));
    assert(result.status === "accepted" || result.status === "duplicate", "psbt frame ok");
  }
  assert(psbtDecoder.state.phase === "complete", "psbt decoder completes");
  const psbtDecoded = psbtDecoder.state.phase === "complete" ? psbtDecoder.state.value : undefined;
  const psbt = fromUr(Ur.fromDecoded(must(psbtDecoded)), psbtCodec);
  eq(bytesToHex(psbt.bytes), bytesToHex(psbtBytes), "psbt multipart round trip");
}
