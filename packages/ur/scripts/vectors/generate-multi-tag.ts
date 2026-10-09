/**
 * Generates `vectors/typed/multi-tag.json`: codec dispatch contract for a tagged type registered
 * under two names (write-first-tag / read-any-tag semantics).
 *
 * Usage: bun packages/ur/scripts/vectors/generate-multi-tag.ts
 */
/// <reference types="node" />
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  CborError,
  CborMap,
  Tag,
  cbor,
  expectMap,
  expectText,
  expectUnsigned,
  bytesToHex,
  encodeCbor,
  taggedValue,
} from "@blockchaincommons/dcbor";
import type { Cbor } from "@blockchaincommons/dcbor";

import { toTagged, toUr } from "../../src/typed/index.ts";
import type { UrCodec } from "../../src/typed/index.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "..", "..", "vectors");

type Note = { id: number; note: string };

const VALUE: Note = { id: 7, note: "hi" };

const codec: UrCodec<Note> = {
  tags: [Tag.from(9999, "x-test"), Tag.from(9998, "x-test-legacy")],
  encode(value) {
    const map = new CborMap();
    map.set(1, value.id);
    map.set(2, value.note);
    return cbor(map);
  },
  decode(value: Cbor): Note {
    const map = expectMap(value);
    const id = map.get(1);
    const note = map.get(2);
    if (id === undefined || note === undefined) {
      throw CborError.wrongType();
    }
    return { id: Number(expectUnsigned(id)), note: expectText(note) };
  },
};

const tagged = toTagged(VALUE, codec);
const [, legacyTag] = codec.tags;
if (legacyTag === undefined) {
  throw new Error("codec.tags[1] missing");
}
const legacyTagged = taggedValue(legacyTag, codec.encode(VALUE));
const uri = toUr(VALUE, codec).toString();

const spec = {
  description:
    "Two-tag codec contract: write uses the first tag name, read accepts any tag name. " +
    "bodyHex is untagged dCBOR of {1: id, 2: note}.",
  type: "x-test",
  legacyType: "x-test-legacy",
  foreignType: "seed",
  primaryTag: 9999,
  legacyTag: 9998,
  id: VALUE.id,
  note: VALUE.note,
  bodyHex: bytesToHex(encodeCbor(codec.encode(VALUE))),
  taggedHex: bytesToHex(encodeCbor(tagged)),
  legacyTaggedHex: bytesToHex(encodeCbor(legacyTagged)),
  uri,
  legacyUri: uri.replace("ur:x-test/", "ur:x-test-legacy/"),
  foreignUri: uri.replace("ur:x-test/", "ur:seed/"),
  expectedTypes: ["x-test", "x-test-legacy"],
};

writeFileSync(join(VECTORS, "typed", "multi-tag.json"), `${JSON.stringify(spec, null, 2)}\n`);
console.log("wrote vectors/typed/multi-tag.json");
console.log(JSON.stringify(spec, null, 2));
