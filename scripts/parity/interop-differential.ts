/// <reference types="node" />
/**
 * Seeded cross-language interop differential. TypeScript generates random valid `btc-sign-request`
 * / `btc-signature` / `qr-hardware-call` values, encodes the untagged body, optionally applies
 * exactly one structural mutation, and records the decode outcome. The Rust replay test
 * (`crates/bcur-registry/tests/interop_differential.rs`, driven by `bun run test:parity`) wraps
 * each recorded body in the codec tag and asserts an identical accept/reject error category and,
 * for accepted cases, a byte-identical tagged re-encoding and UR string.
 *
 * Only the public API from `packages/ur/src/interop/index.ts` is used.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import {
  CborError,
  CborMap,
  asArray,
  asBytes,
  asMap,
  asTaggedValue,
  asText,
  asUnsigned,
  cbor,
  decodeCbor,
  encodeCbor,
  extractTaggedContent,
  hexToBytes,
  mapValue,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor, Tag } from "@blockchaincommons/dcbor";

import {
  INTEROP_TAGS,
  btcSignRequestCodec,
  btcSignatureCodec,
  qrHardwareCallCodec,
  toTagged,
  toUr,
} from "../../packages/ur/src/interop/index.ts";
import type {
  BtcSignRequest,
  BtcSignature,
  KeyDerivationAlgorithm,
  KeyDerivationCurve,
  KeyDerivationSchema,
  Keypath,
  PathComponent,
  QrHardwareCall,
  UrCodec,
} from "../../packages/ur/src/interop/index.ts";
import { makeRng, parseArgs, toHex } from "./differential.ts";
import type { Cli, Rng } from "./differential.ts";

const DEFAULT_CASES = 300;
const DEFAULT_OUT = "target/parity/interop-differential.json";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const TEXT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

const CODEC_NAMES = ["btc-sign-request", "btc-signature", "qr-hardware-call"] as const;
type CodecName = (typeof CODEC_NAMES)[number];

const CODECS: Readonly<Record<CodecName, UrCodec<unknown>>> = {
  "btc-sign-request": btcSignRequestCodec,
  "btc-signature": btcSignatureCodec,
  "qr-hardware-call": qrHardwareCallCodec,
};

// random valid values
function randomBytes(rng: Rng, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    bytes[i] = rng.int(0, 255);
  }
  return bytes;
}

function randomText(rng: Rng, alphabet: string, min: number, max: number): string {
  const length = rng.int(min, max);
  let text = "";
  for (let i = 0; i < length; i += 1) {
    text += alphabet.charAt(rng.int(0, alphabet.length - 1));
  }
  return text;
}

/** A concrete path of 1..6 index steps, with optional fingerprint/depth. */
export function randomKeypath(rng: Rng): Keypath {
  const count = rng.int(1, 6);
  const components: PathComponent[] = [];
  for (let i = 0; i < count; i += 1) {
    components.push({ kind: "index", index: rng.int(0, 0x7fffffff), hardened: rng.chance(0.5) });
  }
  const fingerprint = rng.chance(0.5) ? rng.int(1, 0xffffffff) : undefined;
  const depth = rng.chance(0.5) ? count : undefined;
  return {
    components,
    ...(fingerprint === undefined ? {} : { sourceFingerprint: fingerprint }),
    ...(depth === undefined ? {} : { depth }),
  };
}

function randomBtcSignRequest(rng: Rng): BtcSignRequest {
  const pathCount = rng.int(1, 4);
  const derivationPaths: Keypath[] = [];
  for (let i = 0; i < pathCount; i += 1) {
    derivationPaths.push(randomKeypath(rng));
  }
  const addresses = rng.chance(0.5)
    ? Array.from({ length: rng.int(1, 3) }, () => randomText(rng, B58, 8, 34))
    : undefined;
  const origin = rng.chance(0.5) ? randomText(rng, TEXT, 3, 16) : undefined;
  return {
    requestId: randomBytes(rng, 16),
    signData: randomBytes(rng, rng.int(1, 64)),
    dataType: "message",
    derivationPaths,
    ...(addresses === undefined ? {} : { addresses }),
    ...(origin === undefined ? {} : { origin }),
  };
}

function randomBtcSignature(rng: Rng): BtcSignature {
  return {
    requestId: randomBytes(rng, 16),
    signature: randomBytes(rng, 65),
    publicKey: randomBytes(rng, 33),
  };
}

const CURVES: ReadonlyArray<KeyDerivationCurve> = ["secp256k1", "ed25519"];
const ALGORITHMS: ReadonlyArray<KeyDerivationAlgorithm> = ["slip10", "bip32Ed25519"];

function randomSchema(rng: Rng): KeyDerivationSchema {
  const curve = rng.chance(0.6) ? rng.pick(CURVES) : undefined;
  const algorithm = rng.chance(0.6) ? rng.pick(ALGORITHMS) : undefined;
  const chainType = rng.chance(0.3) ? randomText(rng, TEXT, 2, 8).toUpperCase() : undefined;
  return {
    keyPath: randomKeypath(rng),
    ...(curve === undefined ? {} : { curve }),
    ...(algorithm === undefined ? {} : { algorithm }),
    ...(chainType === undefined ? {} : { chainType }),
  };
}

function randomHwCall(rng: Rng): QrHardwareCall {
  const schemaCount = rng.int(1, 5);
  const schemas: KeyDerivationSchema[] = [];
  for (let i = 0; i < schemaCount; i += 1) {
    schemas.push(randomSchema(rng));
  }
  const origin = rng.chance(0.4) ? randomText(rng, TEXT, 3, 16) : undefined;
  const version = rng.chance(0.5) ? rng.pick([0, 1] as const) : undefined;
  return {
    params: { kind: "keyDerivation", schemas },
    ...(origin === undefined ? {} : { origin }),
    ...(version === undefined ? {} : { version }),
  };
}

const VALUE_BUILDERS: Readonly<Record<CodecName, (rng: Rng) => unknown>> = {
  "btc-sign-request": randomBtcSignRequest,
  "btc-signature": randomBtcSignature,
  "qr-hardware-call": randomHwCall,
};

function randomValue(name: CodecName, rng: Rng): unknown {
  return VALUE_BUILDERS[name](rng);
}

// untagged-body mutation
type Entry = Readonly<{ k: number; v: Cbor }>;

function entriesOf(body: Cbor): Entry[] {
  const map = asMap(body);
  if (map === undefined) {
    throw new Error("interop-differential: untagged body is not a map");
  }
  return map.entriesArray.map((entry) => ({
    k: Number(asUnsigned(entry.key)),
    v: entry.value,
  }));
}

function mapOf(entries: ReadonlyArray<Entry>): Cbor {
  const map = new CborMap();
  for (const { k, v } of entries) {
    map.set(k, v);
  }
  return cbor(map);
}

function resizeBytes(bytes: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  out.set(bytes.slice(0, Math.min(bytes.length, length)));
  return out;
}

/** A byte field: `tagged` means `#6.37`-wrapped, `empty` forces zero length. */
type ByteField = Readonly<{ key: number; tagged: boolean; empty: boolean }>;

function byteFields(name: CodecName, context: string): ReadonlyArray<ByteField> {
  if (context !== "body") {
    return [];
  }
  const requestId: ByteField = { key: 1, tagged: true, empty: false };
  if (name === "btc-sign-request") {
    return [requestId, { key: 2, tagged: false, empty: true }];
  }
  if (name === "btc-signature") {
    return [
      requestId,
      { key: 2, tagged: false, empty: false },
      { key: 3, tagged: false, empty: false },
    ];
  }
  return [];
}

function enumKeys(name: CodecName, context: string): ReadonlyArray<number> {
  if (context === "body") {
    return name === "btc-sign-request" ? [3] : [];
  }
  if (context === "call") {
    return [1, 4];
  }
  if (context === "schema") {
    return [2, 3];
  }
  return [];
}

const MUTATION_KINDS = [
  "drop-key",
  "unknown-key",
  "wrong-type",
  "byte-length",
  "enum-range",
] as const;
type MutationKind = (typeof MUTATION_KINDS)[number];

function kindsFor(name: CodecName, context: string, entries: ReadonlyArray<Entry>): MutationKind[] {
  const present = new Set(entries.map((e) => e.k));
  const kinds: MutationKind[] = ["drop-key", "unknown-key", "wrong-type"];
  if (byteFields(name, context).some((f) => present.has(f.key))) {
    kinds.push("byte-length");
  }
  if (enumKeys(name, context).some((k) => present.has(k))) {
    kinds.push("enum-range");
  }
  return kinds;
}

function wrongMajor(value: Cbor): Cbor {
  return asText(value) === undefined ? cbor("x") : cbor(0);
}

function mutateByteField(field: ByteField, value: Cbor, rng: Rng): Cbor {
  if (field.tagged) {
    const tagged = asTaggedValue(value);
    if (tagged === undefined) {
      throw new Error("interop-differential: byte field is not tagged");
    }
    const [tag, content] = tagged;
    const bytes = asBytes(content);
    if (bytes === undefined) {
      throw new Error("interop-differential: tagged byte field is not bytes");
    }
    const length = bytes.length + rng.pick([-1, 1] as const);
    return taggedValue(tag, cbor(resizeBytes(bytes, length)));
  }
  const bytes = asBytes(value);
  if (bytes === undefined) {
    throw new Error("interop-differential: byte field is not bytes");
  }
  const length = field.empty ? 0 : bytes.length + rng.pick([-1, 1] as const);
  return cbor(resizeBytes(bytes, length));
}

function applyKind(
  kind: MutationKind,
  name: CodecName,
  context: string,
  entries: ReadonlyArray<Entry>,
  rng: Rng,
): Entry[] {
  const index = rng.int(0, entries.length - 1);
  if (kind === "drop-key") {
    return entries.filter((_, i) => i !== index);
  }
  if (kind === "unknown-key") {
    const present = new Set(entries.map((e) => e.k));
    let key = 1;
    while (present.has(key)) {
      key += 1;
    }
    return [...entries, { k: key, v: cbor(0) }];
  }
  if (kind === "wrong-type") {
    return entries.map((e, i) => (i === index ? { k: e.k, v: wrongMajor(e.v) } : e));
  }
  if (kind === "byte-length") {
    const present = new Set(entries.map((e) => e.k));
    const field = rng.pick(byteFields(name, context).filter((f) => present.has(f.key)));
    return entries.map((e) =>
      e.k === field.key ? { k: e.k, v: mutateByteField(field, e.v, rng) } : e,
    );
  }
  const present = new Set(entries.map((e) => e.k));
  const key = rng.pick(enumKeys(name, context).filter((k) => present.has(k)));
  return entries.map((e) => (e.k === key ? { k: e.k, v: cbor(rng.int(2, 9)) } : e));
}

// qr-hardware-call nested-map access and rebuild
function hwSchemas(body: Cbor): ReadonlyArray<Cbor> {
  const params = mapValue(body, 2);
  if (params === undefined) {
    throw new Error("interop-differential: qr-hardware-call body lacks key 2");
  }
  const schemas = mapValue(extractTaggedContent(params), 1);
  if (schemas === undefined) {
    throw new Error("interop-differential: key-derivation params lack key 1");
  }
  return asArray(schemas) ?? [];
}

function setHwParams(body: Cbor, params: Cbor): Cbor {
  const tag: Tag = INTEROP_TAGS["key-derivation-call"];
  return mapOf(
    entriesOf(body).map((e) => (e.k === 2 ? { k: e.k, v: taggedValue(tag, params) } : e)),
  );
}

function setHwSchema(body: Cbor, index: number, schema: Cbor): Cbor {
  const tag: Tag = INTEROP_TAGS["key-derivation-schema"];
  const schemas = hwSchemas(body).map((s, i) => (i === index ? taggedValue(tag, schema) : s));
  const params = mapValue(body, 2);
  if (params === undefined) {
    throw new Error("interop-differential: qr-hardware-call body lacks key 2");
  }
  const updated = entriesOf(extractTaggedContent(params)).map((e) =>
    e.k === 1 ? { k: e.k, v: cbor([...schemas]) } : e,
  );
  return setHwParams(body, mapOf(updated));
}

export type InteropMutation = Readonly<{ kind: string; context: string }>;

function mutateBody(
  name: CodecName,
  body: Cbor,
  rng: Rng,
  ordinal: number,
): { body: Cbor; mutation: InteropMutation } {
  let context = "body";
  let entries = entriesOf(body);
  let schemaIndex = -1;
  if (name === "qr-hardware-call") {
    context = rng.pick(["call", "params", "schema"] as const);
    if (context === "params") {
      const params = mapValue(body, 2);
      if (params === undefined) {
        throw new Error("interop-differential: qr-hardware-call body lacks key 2");
      }
      entries = entriesOf(extractTaggedContent(params));
    } else if (context === "schema") {
      const schemas = hwSchemas(body);
      schemaIndex = rng.int(0, schemas.length - 1);
      const schema = schemas[schemaIndex];
      const tagged = schema === undefined ? undefined : asTaggedValue(schema);
      if (tagged === undefined) {
        throw new Error("interop-differential: schema is not tagged");
      }
      entries = entriesOf(tagged[1]);
    }
  }
  const kinds = kindsFor(name, context, entries);
  const kind = kinds[ordinal % kinds.length];
  if (kind === undefined) {
    throw new Error("interop-differential: no applicable mutation kind");
  }
  const updated = applyKind(kind, name, context, entries, rng);
  if (context === "params") {
    return { body: setHwParams(body, mapOf(updated)), mutation: { kind, context } };
  }
  if (context === "schema") {
    return { body: setHwSchema(body, schemaIndex, mapOf(updated)), mutation: { kind, context } };
  }
  return { body: mapOf(updated), mutation: { kind, context } };
}

// case generation
export type InteropOutcome =
  | Readonly<{ accepted: true; cborHex: string; ur: string }>
  | Readonly<{ accepted: false; code: string }>;

export type InteropCase = {
  codec: CodecName;
  /** Untagged dCBOR body (after the optional mutation). */
  inputCborHex: string;
  mutation?: InteropMutation;
  outcome: InteropOutcome;
};

export type InteropFile = {
  schema: 1;
  seed: number;
  cases: InteropCase[];
};

export function generateInteropCase(rng: Rng, ordinal: number): InteropCase {
  const name = rng.pick(CODEC_NAMES);
  const codec = CODECS[name];
  let body = codec.encode(randomValue(name, rng));
  let mutation: InteropMutation | undefined;
  if (rng.chance(2 / 3)) {
    ({ body, mutation } = mutateBody(name, body, rng, ordinal));
  }
  const inputCborHex = toHex(encodeCbor(body));
  let outcome: InteropOutcome;
  try {
    const decoded = codec.decode(decodeCbor(hexToBytes(inputCborHex)));
    outcome = {
      accepted: true,
      cborHex: toHex(encodeCbor(toTagged(decoded, codec))),
      ur: toUr(decoded, codec).toString(),
    };
  } catch (error) {
    if (!CborError.isCborError(error)) {
      throw error;
    }
    outcome = { accepted: false, code: error.code };
  }
  return {
    codec: name,
    inputCborHex,
    ...(mutation === undefined ? {} : { mutation }),
    outcome,
  };
}

export function generateInteropFile(cli: Cli): InteropFile {
  const rng = makeRng(cli.seed);
  const cases: InteropCase[] = [];
  let ordinal = 0;
  for (let i = 0; i < cli.cases; i += 1) {
    const c = generateInteropCase(rng, ordinal);
    if (c.mutation !== undefined) {
      ordinal += 1;
    }
    cases.push(c);
  }
  return { schema: 1, seed: cli.seed, cases };
}

if (import.meta.main) {
  const cli = parseArgs(process.argv.slice(2), { cases: DEFAULT_CASES, out: DEFAULT_OUT });
  const file = generateInteropFile(cli);
  const out = resolve(cli.out);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(file)}\n`);
  console.log(`interop-differential: ${file.cases.length} cases (seed ${cli.seed}) -> ${cli.out}`);
}
