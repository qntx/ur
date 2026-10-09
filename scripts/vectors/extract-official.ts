/**
 * Extract the official UR conformance vectors into `vectors/official/`.
 *
 * Usage: bun scripts/vectors/extract-official.ts
 *
 * Sources are fetched from raw.githubusercontent.com at pinned commits so the output is
 * reproducible. Every extractor is anchored to a test function or doc code block: a missing pattern
 * or wrong count fails the run. Where a vector exists in more than one source it is extracted from
 * the primary source (BCR-2024-001 > URKit > bc-ur) and the script asserts the other sources agree
 * byte-for-byte. Output is byte-stable (sorted keys, 2-space JSON, trailing newline).
 *
 * BCR-2020-005 papers/bcr-2020-005-ur.md single/multi-part UR forms BCR-2020-006
 * papers/bcr-2020-006-urtypes.md seed / psbt registry vectors BCR-2020-007
 * papers/bcr-2020-007-hdkey.md hdkey registry vectors BCR-2020-011 papers/bcr-2020-011-sskr.md sskr
 * registry vectors BCR-2020-012 papers/bcr-2020-012-bytewords.md bytewords vectors BCR-2024-001
 * papers/bcr-2024-001-multipart-ur.md MUR consensus + fountain vectors URKit
 * Tests/URKitTests/*.swift reference test suite bc-ur test/test.cpp reference test suite
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  balanced,
  codeBlockAfter,
  codeBlockContaining,
  concatString,
  docFuncBody,
  expect,
  fail,
  funcBody,
  hexLiteral,
  intList,
  intMatrix,
  multilineString,
  numbers,
  req,
  stringLiterals,
  urLiterals,
} from "./parse.ts";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  sleep: (ms: number) => Promise<void>;
};

const RESEARCH_SHA = "e4a4fbb186e2e7625ccdf7149aec4f0a5adaf850";
const URKIT_SHA = "ebba59b2e1538cb368d98147dd58c452e6d1dc47";
const BCUR_SHA = "4479fb81b2350ae8bafa042a5572b9c64c2c32ca";
const BCUR_RS_SHA = "2f8b4e728945f9dc248eba71911b89371f076924";

const URKIT_FOUNTAIN = `URKit ${URKIT_SHA} Tests/URKitTests/FountainCodesTests.swift`;
const URKIT_BYTEWORDS = `URKit ${URKIT_SHA} Tests/URKitTests/BytewordsTests.swift`;
const URKIT_UR = `URKit ${URKIT_SHA} Tests/URKitTests/URTests.swift`;
const BCUR_TEST = `bc-ur ${BCUR_SHA} test/test.cpp`;
const BCUR_RS_BYTEWORDS = `bc-ur-rust ${BCUR_RS_SHA} src/bytewords.rs`;

const VECTORS = join(import.meta.dirname, "../../vectors");

type Json = Record<string, unknown>;
const log: string[] = [];

async function fetchRaw(repo: string, sha: string, path: string): Promise<string> {
  const url = `https://raw.githubusercontent.com/${repo}/${sha}/${path}`;
  const attempt = async (remaining: number): Promise<string> => {
    const res = await fetch(url, { headers: { "User-Agent": "qntx-ur-vectors" } }).catch(
      (error: unknown) => error,
    );
    if (res instanceof Response && res.ok) {
      return res.text();
    }
    if (remaining > 1) {
      await Bun.sleep(400 * (4 - remaining));
      return attempt(remaining - 1);
    }
    const detail = res instanceof Response ? `HTTP ${res.status}` : String(res);
    return fail(`fetch failed for ${url}: ${detail}`);
  };
  return attempt(3);
}

/** Assert every `other` equals `value` (deep), then return `value`. */
function crossChecked<T>(value: T, others: T[], label: string): T {
  const canon = JSON.stringify(value);
  for (const [i, other] of others.entries()) {
    expect(JSON.stringify(other) === canon, `cross-check mismatch for ${label} (source ${i + 1})`);
  }
  log.push(`ok ${label}`);
  return value;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .toSorted(([a], [b]) => (a < b ? -1 : 1))
        .map(([k, v]) => [k, sortKeys(v)]),
    );
  }
  return value;
}

const written: string[] = [];

function writeVector(rel: string, capability: string, source: Json, cases: Json[]): void {
  expect(cases.length > 0, `${rel}: no cases`);
  const out = `${JSON.stringify(sortKeys({ schema: 1, capability, source, cases }), null, 2)}\n`;
  const dest = join(VECTORS, rel);
  mkdirSync(join(dest, ".."), { recursive: true });
  writeFileSync(dest, out);
  written.push(`${rel} (${cases.length})`);
}

function murSource(): Json {
  return {
    kind: "official",
    name: "BCR-2024-001",
    revision: RESEARCH_SHA,
    path: "papers/bcr-2024-001-multipart-ur.md",
    crossChecked: [URKIT_FOUNTAIN, BCUR_TEST],
  };
}

function researchSource(name: string, path: string, crossChecked: string[] = []): Json {
  return { kind: "official", name, revision: RESEARCH_SHA, path, crossChecked };
}

/** `find…FragmentLength(…)` call args + asserted result, per assert site. */
function fragmentLengthCalls(body: string): Json[] {
  const re = /find\w*[fF]ragment\w*\(([^)]*)\)\s*(?:,|==)\s*([\d_]+)/g;
  const out: Json[] = [];
  for (const m of body.matchAll(re)) {
    const args = numbers(req(m[1], "call args"));
    expect(args.length === 3, `fragment-length call args: ${m[0]}`);
    out.push({
      messageLength: args[0],
      minFragmentLength: args[1],
      maxFragmentLength: args[2],
      expected: numbers(req(m[2], "expected"))[0],
    });
  }
  return out;
}

/** `(seqNum…, …, checksum, data)` argument list of a Part construction. */
function partFields(body: string): { fields: number[]; data: number[] } {
  const i = body.indexOf("Part(");
  expect(i !== -1, "part-cbor: missing Part construction");
  const ns = numbers(balanced(body, i + 4));
  expect(ns.length >= 4, `part-cbor: too few fields (${ns.length})`);
  return { fields: ns.slice(0, 4), data: ns.slice(4) };
}

/* ------------------------------------------------------------------ mur */

function mur(bcr: string, kit: string, cpp: string): void {
  const b = (name: string) => docFuncBody(bcr, name);
  const k = (name: string) => funcBody(kit, `func ${name}`);
  const c = (name: string) => funcBody(cpp, `void ${name}`);

  /* crc32 */

  const crc1 = crossChecked(
    Number.parseInt(/checksum,\s*0x([0-9a-f]+)/.exec(b("testCRC32"))?.[1] ?? "", 16),
    [Number.parseInt(/checksum\s*==\s*0x([0-9a-f]+)/.exec(k("testCRC32"))?.[1] ?? "", 16)],
    "crc32 testCRC32 BCR==URKit",
  );
  const crcWolfOut = {
    name: "testCRC32",
    inputUtf8: "Wolf",
    checksum: crc1.toString(16).padStart(8, "0"),
  };

  const crc2Bcr = b("testCRC32_2");
  const crc2Input = hexLiteral(crc2Bcr, "toData");
  const crc2 = crossChecked(
    Number.parseInt(/checksum,\s*0x([0-9a-f]+)/.exec(crc2Bcr)?.[1] ?? "", 16),
    [Number.parseInt(/checksum\s*==\s*0x([0-9a-f]+)/.exec(k("testCRC32_2"))?.[1] ?? "", 16)],
    "crc32 testCRC32_2 BCR==URKit",
  );

  const crcCpp = c("test_crc32");
  const crcPairs = [...crcCpp.matchAll(/_test_crc32\("([^"]*)",\s*"([0-9a-f]+)"\)/g)].map((m) => ({
    inputUtf8: m[1],
    checksum: m[2],
  }));
  expect(crcPairs.length === 2, `test_crc32: expected 2 inputs, got ${crcPairs.length}`);
  const crcWolfCpp = crcPairs.find((p) => p.inputUtf8 === "Wolf");
  crossChecked(crcWolfOut.checksum, [crcWolfCpp?.checksum], "crc32 Wolf BCR/URKit==bc-ur");
  const crcHello = crcPairs.find((p) => p.inputUtf8 !== "Wolf");
  expect(crcHello !== undefined, "test_crc32: missing second case");

  writeVector("official/mur/crc32.json", "consensus.crc32", murSource(), [
    crcWolfOut,
    {
      name: "testCRC32_2",
      inputHex: crc2Input,
      checksum: crc2.toString(16).padStart(8, "0"),
    },
    { name: "bc-ur test_crc32", inputUtf8: crcHello.inputUtf8, checksum: crcHello.checksum },
  ]);

  /* rng */

  const rngParams: Json[] = [
    { name: "testRNG1", seed: { string: "Wolf" }, op: "nextMod", args: { modulus: 100 } },
    { name: "testRNG2", seed: { crc32OfUtf8: "Wolf" }, op: "nextMod", args: { modulus: 100 } },
    { name: "testRNG3", seed: { string: "Wolf" }, op: "nextInt", args: { low: 1, high: 10 } },
  ];
  const rngCases: Json[] = rngParams.map((params, i) => {
    const n = i + 1;
    const bcrList = intList(b(`testRNG${n}`), "expectedNumbers");
    const kitList = intList(k(`testRNG${n}`), "expectedNumbers");
    const cppList = intList(c(`test_rng_${n}`), "expected_numbers");
    expect(bcrList.length === 100, `testRNG${n}: expected 100 samples`);
    const expected = crossChecked(bcrList, [kitList, cppList], `rng testRNG${n} all==`);
    return Object.assign(params, { count: 100, expected });
  });

  const nextData = (
    [
      [/data1\.hex,\s*"([0-9a-f]+)"/, /data2\.hex,\s*"([0-9a-f]+)"/],
      [/data1\.hex\s*==\s*"([0-9a-f]+)"/, /data2\.hex\s*==\s*"([0-9a-f]+)"/],
      [/data_to_hex\(data1\)\s*==\s*"([0-9a-f]+)"/, /data_to_hex\(data2\)\s*==\s*"([0-9a-f]+)"/],
    ] as const
  ).map((res, i) => {
    const body = req([b("testXOR"), k("testXOR"), c("test_xor")][i], `testXOR body ${i}`);
    const pair = res.map((re) => re.exec(body)?.[1]);
    expect(
      pair.every((v) => v !== undefined),
      `testXOR: missing literal in source ${i}`,
    );
    return pair;
  });
  const [nextDataBcr, nextDataKit, nextDataCpp] = nextData;
  const data = crossChecked(nextDataBcr, [nextDataKit, nextDataCpp], "rng nextData all==");
  rngCases.push({
    name: "testXOR nextData",
    seed: { string: "Wolf" },
    op: "nextData",
    args: { length: 10 },
    count: 2,
    expected: data,
  });
  writeVector("official/mur/rng.json", "consensus.xoshiro", murSource(), rngCases);

  /* fragment length */

  const fragLen = crossChecked(
    fragmentLengthCalls(b("testFindFragmentLength")),
    [
      fragmentLengthCalls(k("testFindFragmentLength")),
      fragmentLengthCalls(c("test_find_fragment_length")),
    ],
    "fragment-length all==",
  );
  expect(fragLen.length === 2, "fragment-length: expected 2 cases");
  writeVector(
    "official/mur/fragment-length.json",
    "fountain.fragment-length",
    murSource(),
    fragLen,
  );

  /* partition */

  const partitionLists = [
    b("testPartitionAndJoin"),
    k("testPartitionAndJoin"),
    c("test_partition_and_join"),
  ].map((body) => {
    const list = stringLiterals(bracketBlockLocal(body, "expected"));
    expect(list.length === 11, `partition: expected 11, got ${list.length}`);
    return list;
  });
  const fragments = crossChecked(
    req(partitionLists[0], "partition bcr"),
    [req(partitionLists[1], "partition kit"), req(partitionLists[2], "partition cpp")],
    "partition all==",
  );
  writeVector("official/mur/partition.json", "fountain.partition", murSource(), [
    {
      message: { seed: "Wolf", length: 1024 },
      minFragmentLength: 10,
      maxFragmentLength: 100,
      fragmentsHex: fragments,
    },
  ]);

  /* degree chooser + random sampler */

  const degreeBodies = [b("testDegreeChooser"), k("testDegreeChooser")];
  const degreeBcr = req(degreeBodies[0], "degree bcr");
  const degreeKit = req(degreeBodies[1], "degree kit");
  const degrees = intList(degreeBcr, "expectedDegrees");
  const degreesKit = intList(degreeKit, "expectedDegrees");
  expect(degrees.length === 1000, `degree: expected 1000, got ${degrees.length}`);
  crossChecked(degrees, [degreesKit], "degree list BCR==URKit");
  const degreeTotals = assertListLiteral(degreeBcr, "sortedDegrees");
  const degreeTotalsKit = assertListLiteral(degreeKit, "sortedDegrees");
  crossChecked(degreeTotals, [degreeTotalsKit], "degree totals BCR==URKit");

  const cppDegreeBody = c("test_choose_degree");
  const cppDegrees = intList(cppDegreeBody, "expected_degrees");
  expect(cppDegrees.length === 200, `bc-ur degree: expected 200, got ${cppDegrees.length}`);
  expect(
    cppDegreeBody.includes('"Wolf-" + to_string(nonce)'),
    "bc-ur degree: missing Wolf- nonce seeding",
  );

  const samplerBodies = [b("testRandomSampler"), k("testRandomSampler"), c("test_random_sampler")];
  const samplerBcr = req(samplerBodies[0], "sampler bcr");
  const samplerKit = req(samplerBodies[1], "sampler kit");
  const sampleLists = samplerBodies.map((body, i) => {
    const list = intList(body, i === 2 ? "expected_samples" : "expectedSamples");
    expect(list.length === 500, `sampler: expected 500, got ${list.length}`);
    return list;
  });
  const samples = crossChecked(
    req(sampleLists[0], "sampler bcr list"),
    [req(sampleLists[1], "sampler kit list"), req(sampleLists[2], "sampler cpp list")],
    "sampler all==",
  );
  const samplerTotals = assertListLiteral(samplerBcr, "sortedValues");
  const samplerTotalsKit = assertListLiteral(samplerKit, "sortedValues");
  crossChecked(samplerTotals, [samplerTotalsKit], "sampler totals BCR==URKit");

  writeVector("official/mur/degree.json", "consensus.sampler", murSource(), [
    {
      name: "testDegreeChooser",
      kind: "degree-chooser",
      message: { seed: "Wolf", length: 1024 },
      minFragmentLength: 10,
      maxFragmentLength: 100,
      rngSeed: "Wolf",
      count: 1000,
      degrees,
      totals: degreeTotals,
    },
    {
      name: "bc-ur test_choose_degree",
      kind: "degree-chooser-per-nonce",
      message: { seed: "Wolf", length: 1024 },
      minFragmentLength: 10,
      maxFragmentLength: 100,
      rngSeed: "Wolf-{n}",
      count: 200,
      degrees: cppDegrees,
    },
    {
      name: "testRandomSampler",
      kind: "random-sampler",
      probabilities: [1, 2, 4, 8],
      rngSeed: "Wolf",
      count: 500,
      samples,
      totals: samplerTotals,
    },
  ]);

  /* shuffle */

  const prefixBodies = [b("testShuffle"), k("testShuffle")];
  const prefixBcr = req(prefixBodies[0], "shuffle bcr");
  const prefixRows = prefixBodies.map((body) => {
    const rows = intMatrix(body, "expectedResult");
    expect(rows.length === 10, `shuffle: expected 10 rows, got ${rows.length}`);
    return rows;
  });
  const prefixes = crossChecked(
    req(prefixRows[0], "shuffle rows bcr"),
    [req(prefixRows[1], "shuffle rows kit")],
    "shuffle prefixes BCR==URKit",
  );

  const range = /indexes = (\d+)\.\.\.(\d+)/.exec(prefixBcr);
  expect(range !== null, "shuffle: missing value range");
  const [lo, hi] = [Number(range[1]), Number(range[2])];
  const values = Array.from({ length: hi - lo + 1 }, (_, i) => i + lo);

  const cppShuffle = c("test_shuffle");
  const cppValues = numbers(bracketBlockLocal(cppShuffle, "vector<int> values"));
  crossChecked(values, [cppValues], "shuffle values BCR/URKit==bc-ur");
  const continuedRows = intMatrix(cppShuffle, "expectedResult");
  expect(
    continuedRows.length === 10,
    `bc-ur shuffle: expected 10 rounds, got ${continuedRows.length}`,
  );

  writeVector("official/mur/shuffle.json", "consensus.shuffle", murSource(), [
    ...prefixes.map((expected, i) => ({
      name: `testShuffle count=${i + 1}`,
      kind: "prefix",
      rngSeed: "Wolf",
      values,
      count: i + 1,
      expected,
    })),
    {
      name: "bc-ur test_shuffle",
      kind: "continued",
      rngSeed: "Wolf",
      values,
      count: 10,
      rounds: 10,
      expected: continuedRows,
    },
  ]);

  /* fragment chooser */

  const chooserRows = [b("testFragmentChooser"), k("testFragmentChooser")].map((body) => {
    const rows = intMatrix(body, "expectedFragmentIndexes");
    expect(rows.length === 50, `chooser: expected 50, got ${rows.length}`);
    return rows;
  });
  const indexes = crossChecked(
    req(chooserRows[0], "chooser rows bcr"),
    [req(chooserRows[1], "chooser rows kit")],
    "chooser BCR==URKit",
  );
  const cppIndexes = intMatrix(c("test_choose_fragments"), "expected_fragment_indexes");
  expect(cppIndexes.length === 30, `bc-ur chooser: expected 30, got ${cppIndexes.length}`);
  crossChecked(indexes.slice(0, 30), [cppIndexes], "chooser bc-ur==BCR[0:30]");

  writeVector("official/mur/chooser.json", "consensus.chooser", murSource(), [
    {
      message: { seed: "Wolf", length: 1024 },
      minFragmentLength: 10,
      maxFragmentLength: 100,
      sequences: Array.from({ length: 50 }, (_, i) => i + 1),
      indexes,
    },
  ]);

  /* part cbor */

  const partBodies = [b("testCBOR"), k("testCBOR"), c("test_fountain_cbor")];
  const partParsed = partBodies.map(partFields);
  const part = crossChecked(
    req(partParsed[0], "part fields bcr"),
    [req(partParsed[1], "part fields kit"), req(partParsed[2], "part fields cpp")],
    "part fields all==",
  );
  const partCborHexes = partBodies.slice(0, 2).map((body, i) => {
    const m = (i === 0 ? /cbor\.hex,\s*"([0-9a-f]+)"/ : /cbor\.hex\s*==\s*"([0-9a-f]+)"/).exec(
      body,
    )?.[1];
    expect(m !== undefined, `part-cbor: missing cbor hex (source ${i})`);
    return m;
  });
  const partCborHex = crossChecked(
    req(partCborHexes[0], "part cbor bcr"),
    [req(partCborHexes[1], "part cbor kit")],
    "part cbor hex BCR==URKit",
  );
  writeVector("official/mur/part-cbor.json", "fountain.part-cbor", murSource(), [
    {
      seqNum: part.fields[0],
      seqLen: part.fields[1],
      messageLen: part.fields[2],
      checksum: req(part.fields[3], "part checksum").toString(16).padStart(8, "0"),
      dataHex: part.data.map((x) => x.toString(16).padStart(2, "0")).join(""),
      cborHex: partCborHex,
    },
  ]);

  /* encoder (part descriptions merged with part cbor hex) */

  const encBodies = [b("testEncoder"), k("testEncoder"), c("test_fountain_encoder")];
  const encLists = encBodies.map((body) =>
    stringLiterals(bracketBlockLocal(body, "expected")).map((s) => {
      const m =
        /seqNum:(\d+), seqLen:(\d+), messageLen:(\d+), checksum:(\d+), data:([0-9a-f]+)/.exec(s);
      expect(m !== null, `part description does not parse: ${s}`);
      return {
        seqNum: Number(m[1]),
        seqLen: Number(m[2]),
        messageLen: Number(m[3]),
        checksum: Number(m[4]).toString(16).padStart(8, "0"),
        dataHex: m[5],
      };
    }),
  );
  const encParts = req(encLists[0], "encoder parts bcr");
  expect(encParts.length === 20, `encoder: expected 20 parts, got ${encParts.length}`);
  crossChecked(
    encParts,
    [req(encLists[1], "encoder parts kit"), req(encLists[2], "encoder parts cpp")],
    "encoder parts all==",
  );

  const encCborBodies = [
    b("testEncoderCBOR"),
    k("testEncoderCBOR"),
    c("test_fountain_encoder_cbor"),
  ];
  const encCborLists = encCborBodies.map((body) =>
    stringLiterals(bracketBlockLocal(body, "expected")),
  );
  const encCborBcr = req(encCborLists[0], "encoder cbor bcr");
  expect(encCborBcr.length === 20, `encoder cbor: expected 20, got ${encCborBcr.length}`);
  const encCbor = crossChecked(
    encCborBcr,
    [req(encCborLists[1], "encoder cbor kit"), req(encCborLists[2], "encoder cbor cpp")],
    "encoder cbor all==",
  );

  const merged = encParts.map((p, i) => ({ ...p, cborHex: encCbor[i] }));
  const seqLen = encParts[0]?.seqLen;
  expect(seqLen !== undefined, "encoder: missing first part seqLen");
  writeVector("official/mur/encoder.json", "fountain.encoder", murSource(), [
    {
      name: "testEncoder",
      kind: "parts",
      message: { seed: "Wolf", length: 256 },
      maxFragmentLength: 30,
      parts: merged,
    },
    {
      name: "testEncoderIsComplete",
      kind: "complete",
      message: { seed: "Wolf", length: 256 },
      maxFragmentLength: 30,
      expectCompleteAfterParts: seqLen,
    },
  ]);

  /* decoder */

  const decBodies = [b("testDecoder"), k("testDecoder"), c("test_fountain_decoder")];
  const decParams = decBodies.map((body, i) => {
    const size = Number(
      (i === 2 ? /message_size\s*=\s*(\d+)/ : /messageSize\s*=\s*(\d+)/).exec(body)?.[1],
    );
    const fragLen = Number(
      (i === 2 ? /max_fragment_len\s*=\s*(\d+)/ : /maxFragmentLen\s*=\s*(\d+)/).exec(body)?.[1],
    );
    const first = Number(
      (i === 2
        ? /FountainEncoder\(message,\s*max_fragment_len,\s*(\d+)\)/
        : /firstSeqNum:\s*(\d+)/
      ).exec(body)?.[1],
    );
    return { length: size, maxFragmentLength: fragLen, firstSeqNum: first };
  });
  const dec = crossChecked(
    req(decParams[0], "decoder params bcr"),
    [req(decParams[1], "decoder params kit"), req(decParams[2], "decoder params cpp")],
    "decoder params all==",
  );
  expect(
    dec.length === 32767 && dec.maxFragmentLength === 1000 && dec.firstSeqNum === 100,
    `decoder params parse failed: ${JSON.stringify(dec)}`,
  );
  writeVector("official/mur/decoder.json", "fountain.decoder", murSource(), [
    {
      message: { seed: "Wolf", length: dec.length },
      maxFragmentLength: dec.maxFragmentLength,
      firstSeqNum: dec.firstSeqNum,
    },
  ]);
}

/** Bracket block after `marker` inside a (pre-extracted) function body. */
function bracketBlockLocal(body: string, marker: string): string {
  const i = body.indexOf(marker);
  expect(i !== -1, `missing '${marker}'`);
  const sq = body.indexOf("[", i);
  const cu = body.indexOf("{", i);
  if (sq !== -1 && (cu === -1 || sq < cu)) {
    return balanced(body, sq);
  }
  expect(cu !== -1, `missing bracket after '${marker}'`);
  return balanced(body, cu);
}

/**
 * `[…]` literal compared against `name` in an assert (`XCTAssertEqual(name, […])` or `name ==
 * […]`).
 */
function assertListLiteral(body: string, name: string): number[] {
  const re = new RegExp(`${name},?\\s*(?:==\\s*)?\\[`, "g");
  let pos = -1;
  for (const m of body.matchAll(re)) {
    pos = m.index + m[0].length - 1;
  }
  expect(pos >= 0, `missing assert list for '${name}'`);
  return numbers(balanced(body, pos));
}

/* ------------------------------------------------------------- bytewords */

const hex = (bytes: number[]) => bytes.map((x) => x.toString(16).padStart(2, "0")).join("");

const style = (body: string, re: RegExp, label: string): string => {
  const m = re.exec(body)?.[1];
  expect(m !== undefined, `bytewords test1: missing ${label}`);
  return m;
};

/** Join the word lines of the first fenced block containing `needle`. */
function wordBlock(markdown: string, needle: string, sep: string): string {
  const block = codeBlockContaining(markdown, needle);
  const lines = block
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^[a-z]+([ -][a-z]+)*-?$/.test(l));
  expect(lines.length > 0, `bytewords block '${needle}': no word lines`);
  return lines.join(sep);
}

function bytewords(bwDoc: string, kitBw: string, cpp: string): void {
  const kit1 = funcBody(kitBw, "func test1");
  const cpp1 = funcBody(cpp, "void test_bytewords_1");

  const input1 = numbers(bracketBlockLocal(kit1, "let input"));
  const input1Cpp = numbers(bracketBlockLocal(cpp1, "ByteVector input"));
  crossChecked(input1, [input1Cpp], "bytewords test1 input URKit==bc-ur");
  const std = crossChecked(
    style(kit1, /style: \.standard\) == "([^"]+)"/, "standard"),
    [style(cpp1, /style::standard, input\) == "([^"]+)"/, "standard")],
    "bytewords std URKit==bc-ur",
  );
  const uri = crossChecked(
    style(kit1, /style: \.uri\) == "([^"]+)"/, "uri"),
    [style(cpp1, /style::uri, input\) == "([^"]+)"/, "uri")],
    "bytewords uri URKit==bc-ur",
  );
  const mini = crossChecked(
    style(kit1, /style: \.minimal\) == "([^"]+)"/, "minimal"),
    [style(cpp1, /style::minimal, input\) == "([^"]+)"/, "minimal")],
    "bytewords minimal URKit==bc-ur",
  );

  const failStart = kit1.indexOf("// bad checksum");
  expect(failStart !== -1, "bytewords test1: missing failure section");
  const kitFails = [
    ...kit1.slice(failStart).matchAll(/decode\("([^"]*)",\s*style: \.(\w+)\)/g),
  ].map((m) => ({ input: req(m[1], "fail input"), style: req(m[2], "fail style") }));
  const cppFails = [
    ...cpp1.matchAll(/assert_throws\(Bytewords::decode\(Bytewords::style::(\w+),\s*"([^"]*)"\)\)/g),
  ].map((m) => ({ input: req(m[2], "fail input"), style: req(m[1], "fail style") }));
  expect(kitFails.length === 5, `bytewords failures: expected 5, got ${kitFails.length}`);
  crossChecked(kitFails, [cppFails], "bytewords failure inputs URKit==bc-ur");

  const kit2 = funcBody(kitBw, "func test2");
  const cpp2 = funcBody(cpp, "void test_bytewords_2");
  const input2 = numbers(bracketBlockLocal(kit2, "let input"));
  const input2Cpp = numbers(bracketBlockLocal(cpp2, "ByteVector input"));
  expect(input2.length === 100, `bytewords test2: expected 100 bytes, got ${input2.length}`);
  crossChecked(input2, [input2Cpp], "bytewords test2 input URKit==bc-ur");
  const std2 = crossChecked(
    multilineString(kit2, "let encoded "),
    [concatString(cpp2, "string encoded ")],
    "bytewords test2 std URKit==bc-ur",
  );
  const mini2 = crossChecked(
    multilineString(kit2, "let encodedMinimal"),
    [concatString(cpp2, "string encoded_minimal")],
    "bytewords test2 minimal URKit==bc-ur",
  );

  const taggedHex = hexLiteral(codeBlockContaining(bwDoc, "d99d6ca20150c7098580"));
  const bwStd = wordBlock(bwDoc, "tuna next jazz oboe", " ");
  const bwUri = wordBlock(bwDoc, "tuna-next-jazz-oboe", "");
  const bwMin = wordBlock(bwDoc, "tantjzoead", "");
  expect(
    bwUri === bwStd.split(" ").join("-"),
    "BCR-2020-012: uri style inconsistent with standard",
  );

  const brutalHex = hexLiteral(
    codeBlockAfter(bwDoc, "the seed payload used in the example above:"),
  );
  const brutalChecksum = codeBlockAfter(
    bwDoc,
    "can be concatenated with the four-byte checksum",
  ).trim();
  expect(/^[0-9a-f]{8}$/.test(brutalChecksum), "brutal checksum not 4-byte hex");
  const brutalStd = wordBlock(bwDoc, "slot axis limp lava brag", " ");
  const brutalMin = wordBlock(bwDoc, "fgmzepsbtwd", "");

  writeVector(
    "official/bytewords.json",
    "bytewords.codec",
    researchSource("BCR-2020-012", "papers/bcr-2020-012-bytewords.md", [
      URKIT_BYTEWORDS,
      BCUR_TEST,
    ]),
    [
      { name: "test1", inputHex: hex(input1), standard: std, uri, minimal: mini },
      ...kitFails.map((f) => ({
        name: `test1 ${f.style} bad input`,
        style: f.style,
        input: f.input,
        error: "InvalidBytewordsChecksum",
      })),
      { name: "test2", inputHex: hex(input2), standard: std2, minimal: mini2 },
      {
        name: "bcr-2020-012 tagged seed",
        inputHex: taggedHex,
        standard: bwStd,
        uri: bwUri,
        minimal: bwMin,
      },
      {
        name: "bcr-2020-012 brutal encoding",
        inputHex: brutalHex,
        checksum: brutalChecksum,
        standard: brutalStd,
        minimal: brutalMin,
      },
    ],
  );
}

/* --------------------------------------------------------------------- ur */

function ur(kitUr: string, cpp: string, urDoc: string, multipartTable: string[]): void {
  const [kitSingle] = urLiterals(funcBody(kitUr, "func testSinglePartUR"));
  const [cppSingle] = urLiterals(funcBody(cpp, "void test_single_part_ur"));
  expect(kitSingle !== undefined, "single-part UR: missing URKit literal");
  const single = crossChecked(kitSingle, [cppSingle], "single UR URKit==bc-ur");

  const docUrs = urLiterals(urDoc);
  const seedSingle = docUrs.find((u) => u.startsWith("ur:seed/oyadgdst"));
  const seedExample = docUrs.find((u) => u.startsWith("ur:seed/oyadhdeyn"));
  const seedFragment = docUrs.find((u) => u.startsWith("ur:seed/1-3/"));
  expect(
    seedSingle !== undefined && seedExample !== undefined && seedFragment !== undefined,
    "BCR-2020-005: missing seed UR literals",
  );
  const seedCbor = hexLiteral(
    codeBlockAfter(urDoc, "when serialized to hex this untagged CBOR is:"),
  );

  writeVector(
    "official/ur/single.json",
    "ur.parse",
    researchSource("BCR-2020-005", "papers/bcr-2020-005-ur.md", [URKIT_UR, BCUR_TEST]),
    [
      {
        name: "testSinglePartUR",
        urType: "bytes",
        ur: single,
        payload: { cborBstr: { seed: "Wolf", length: 50 } },
      },
      { name: "bcr-2020-005 worked seed", urType: "seed", ur: seedSingle, cborHex: seedCbor },
      { name: "bcr-2020-005 single-part example", urType: "seed", ur: seedExample },
      {
        name: "bcr-2020-005 multipart fragment",
        urType: "seed",
        ur: seedFragment,
        kind: "multi",
        seqNum: 1,
        seqLen: 3,
      },
    ],
  );

  const kitParts = stringLiterals(
    bracketBlockLocal(funcBody(kitUr, "func testEncode"), "expectedParts"),
  );
  const cppParts = stringLiterals(
    bracketBlockLocal(funcBody(cpp, "void test_ur_encoder"), "expected_parts"),
  );
  expect(kitParts.length === 20, `ur encoder: expected 20, got ${kitParts.length}`);
  crossChecked(kitParts, [cppParts], "ur encoder URKit==bc-ur");
  crossChecked(kitParts, [multipartTable], "ur encoder URKit==ur-rs/multipart-20.txt");

  const kitEnc = funcBody(kitUr, "func testEncode");
  const cppEnc = funcBody(cpp, "void test_ur_encoder");
  const encLen = crossChecked(
    Number(/makeMessageUR\(len:\s*(\d+)\)/.exec(kitEnc)?.[1]),
    [Number(/make_message_ur\((\d+)\)/.exec(cppEnc)?.[1])],
    "ur encoder message len URKit==bc-ur",
  );

  const kitMulti = funcBody(kitUr, "func testMultipartUR");
  const cppMulti = funcBody(cpp, "void test_multipart_ur");
  const multi = crossChecked(
    {
      length: Number(/makeMessageUR\(len:\s*(\d+)\)/.exec(kitMulti)?.[1]),
      maxFragmentLength: Number(/maxFragmentLen\s*=\s*(\d+)/.exec(kitMulti)?.[1]),
      firstSeqNum: Number(/firstSeqNum:\s*(\d+)/.exec(kitMulti)?.[1]),
    },
    [
      {
        length: Number(/make_message_ur\((\d+)\)/.exec(cppMulti)?.[1]),
        maxFragmentLength: Number(/max_fragment_len\s*=\s*(\d+)/.exec(cppMulti)?.[1]),
        firstSeqNum: Number(/first_seq_num\s*=\s*(\d+)/.exec(cppMulti)?.[1]),
      },
    ],
    "multipart UR params URKit==bc-ur",
  );
  expect(encLen === 256, "ur encoder: bad message len");
  expect(
    multi.length === 32767 && multi.maxFragmentLength === 1000 && multi.firstSeqNum === 100,
    "multipart UR params parse failed",
  );

  writeVector(
    "official/ur/multipart.json",
    "ur.encoder",
    {
      kind: "official",
      name: "URKit",
      revision: URKIT_SHA,
      path: "Tests/URKitTests/URTests.swift",
      crossChecked: [BCUR_TEST, "ur-rs 9b3064d… vectors/ur-rs/multipart-20.txt"],
    },
    [
      {
        name: "testEncode",
        urType: "bytes",
        wrap: "cbor-bstr",
        message: { seed: "Wolf", length: encLen },
        maxFragmentLength: 30,
        partsFile: "ur-rs/multipart-20.txt",
        partCount: kitParts.length,
      },
      {
        name: "testMultipartUR",
        urType: "bytes",
        wrap: "cbor-bstr",
        message: { seed: "Wolf", length: multi.length },
        maxFragmentLength: multi.maxFragmentLength,
        firstSeqNum: multi.firstSeqNum,
      },
    ],
  );
}

/* -------------------------------------------------------------- registry */

function registry(urtDoc: string, hdkeyDoc: string, sskrDoc: string, urDoc: string): void {
  const seedHex = hexLiteral(codeBlockContaining(urtDoc, "A20150C7098580"));
  const seedUr = urLiterals(urtDoc).find((u) => u.startsWith("ur:seed/"));
  expect(seedUr !== undefined, "BCR-2020-006: missing seed UR");
  const seed5Cbor = hexLiteral(
    codeBlockAfter(urDoc, "when serialized to hex this untagged CBOR is:"),
  );
  const seed5Ur = urLiterals(urDoc).find((u) => u.startsWith("ur:seed/oyadgdst"));
  expect(seed5Ur !== undefined, "BCR-2020-005: missing payload-only seed UR");

  writeVector(
    "official/registry/seed.json",
    "registry.seed",
    researchSource("BCR-2020-006", "papers/bcr-2020-006-urtypes.md", [
      `BCR-2020-005 ${RESEARCH_SHA} papers/bcr-2020-005-ur.md`,
    ]),
    [
      {
        name: "v2 seed, tag-100 creation date",
        urType: "seed",
        tag: 40300,
        cborHex: seedHex,
        ur: seedUr,
        diagnostic: "{ 1: h'c7098580125e2ab0981253468b2dbc52', 2: 100(18394) }",
      },
      {
        name: "payload-only seed (BCR-2020-005)",
        urType: "seed",
        tag: 40300,
        cborHex: seed5Cbor,
        ur: seed5Ur,
      },
    ],
  );

  const psbtHex = hexLiteral(codeBlockContaining(urtDoc, "58A770736274FF"));
  const psbtUr = urLiterals(urtDoc).find((u) => u.startsWith("ur:psbt/"));
  expect(psbtUr !== undefined, "BCR-2020-006: missing psbt UR");
  writeVector(
    "official/registry/psbt.json",
    "registry.psbt",
    researchSource("BCR-2020-006", "papers/bcr-2020-006-urtypes.md"),
    [{ name: "psbt example", urType: "psbt", cborHex: psbtHex, ur: psbtUr }],
  );

  const hdkeyUrs = [...new Set(urLiterals(hdkeyDoc).filter((u) => u.startsWith("ur:hdkey/")))];
  expect(hdkeyUrs.length === 2, `BCR-2020-007: expected 2 hdkey URs, got ${hdkeyUrs.length}`);
  const hdkey1Cbor = hexLiteral(codeBlockContaining(hdkeyDoc, "a301f5035821"));
  const hdkey2Cbor = hexLiteral(codeBlockContaining(hdkeyDoc, "a5035821026fe2"));
  const digestSource = hexLiteral(codeBlockContaining(hdkeyDoc, "845821026fe2355745bb2db"));
  const digest = hexLiteral(
    codeBlockContaining(hdkeyDoc, "362af3038da7600ad1581c19161c8594aafafc24"),
  );
  writeVector(
    "official/registry/hdkey.json",
    "registry.hdkey",
    researchSource("BCR-2020-007", "papers/bcr-2020-007-hdkey.md"),
    [
      {
        name: "BIP32 master (vector 1)",
        urType: "hdkey",
        tag: 40303,
        cborHex: hdkey1Cbor,
        ur: hdkeyUrs[0],
      },
      {
        name: "testnet derived m/44'/1'/1'/0/1 (vector 2)",
        urType: "hdkey",
        tag: 40303,
        cborHex: hdkey2Cbor,
        ur: hdkeyUrs[1],
        digestSourceHex: digestSource,
        digestHex: digest,
      },
    ],
  );

  const shareBlock = codeBlockContaining(sskrDoc, "4bbf1101003e990c1f0435e2b33c721535c74603d0");
  const shareHexes = shareBlock
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^[0-9a-f]{42}$/.test(l));
  expect(shareHexes.length === 8, `BCR-2020-011: expected 8 shares, got ${shareHexes.length}`);
  const bwBlock = codeBlockContaining(sskrDoc, "tuna next keep gyro gear runs body acid able film");
  const shareBws = bwBlock
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => /^([a-z]{4} )+[a-z]{4}$/.test(l));
  expect(
    shareBws.length === 8,
    `BCR-2020-011: expected 8 bytewords shares, got ${shareBws.length}`,
  );
  const urBlock = codeBlockContaining(
    sskrDoc,
    "ur:sskr/gogrrsbyadaefmnlbnctaaecvoqdfnjpbzecstfgaxtifpsskbfw",
  );
  const shareUrs = urLiterals(urBlock);
  expect(shareUrs.length === 8, `BCR-2020-011: expected 8 share URs, got ${shareUrs.length}`);
  const tagged3 = hexLiteral(codeBlockContaining(sskrDoc, "d99d75554bbf1101025abd"));
  const share3 = req(shareHexes[2], "share 3 hex");
  expect(
    tagged3 === `d99d7555${share3}`,
    "BCR-2020-011: derived tagged hex does not match doc literal",
  );
  const masterSecret = hexLiteral(codeBlockContaining(sskrDoc, "7daa851251002874e1a1995f0897e6b1"));
  writeVector(
    "official/registry/sskr.json",
    "registry.sskr",
    researchSource("BCR-2020-011", "papers/bcr-2020-011-sskr.md"),
    [
      {
        name: "2 groups (2-of-3, 3-of-5), group threshold 2",
        masterSecretHex: masterSecret,
        urType: "sskr",
        tag: 40309,
        shares: shareHexes.map((shareHex, i) => ({
          index: i,
          group: i < 3 ? 1 : 2,
          cborHex: `55${shareHex}`,
          taggedCborHex: `d99d7555${shareHex}`,
          bytewords: req(shareBws[i], "share bytewords"),
          ur: req(shareUrs[i], "share ur"),
        })),
      },
    ],
  );
}

/* ------------------------------------------------- identifier/bytemoji */

/** The 256-word table from the BCR-2020-012 `0xNN:` word list. */
function docWordTable(bwDoc: string): string[] {
  const block = codeBlockContaining(bwDoc, "0x00: able acid also apex");
  const words: string[] = [];
  for (const m of block.matchAll(/0x([0-9a-f]{2}):((?: [a-z]{4}){8})/g)) {
    const base = Number.parseInt(req(m[1], "word row base"), 16);
    const row = req(m[2], "word row").trim().split(" ");
    for (const [i, w] of row.entries()) {
      words[base + i] = w;
    }
  }
  expect(
    words.length === 256 && words.every((w) => w !== undefined),
    `BCR-2020-012: word table must hold 256 entries, got ${words.length}`,
  );
  return words;
}

/**
 * The 256-emoji table: BCR-2024-008 reference string cross-checked against the paper's 16x16 table
 * and the pinned bc-ur-rust `BYTEMOJIS` constant.
 */
function docBytemojis(bytemojiDoc: string, bcRs: string): string[] {
  const refBlock = codeBlockAfter(bytemojiDoc, "### Reference String");
  const ref = [...new Intl.Segmenter().segment(refBlock.trim())].map((s) => s.segment);
  expect(ref.length === 256, `BCR-2024-008: reference string has ${ref.length} emojis`);

  const tableRows = bytemojiDoc.split("\n").filter((l) => /^\| [0-9A-F] \|/.test(l));
  expect(tableRows.length === 16, `BCR-2024-008: expected 16 table rows, got ${tableRows.length}`);
  const table: string[] = [];
  for (const row of tableRows) {
    const cells = row
      .split("|")
      .map((c) => c.trim())
      .filter((c) => c.length > 0);
    const emojis = cells.slice(1);
    expect(emojis.length === 16, `BCR-2024-008: row needs 16 emojis, got ${emojis.length}`);
    table.push(...emojis);
  }
  crossChecked(ref, [table], "BCR-2024-008 reference string vs table");

  const rsBlock = bcRs.slice(
    bcRs.indexOf("pub const BYTEMOJIS"),
    bcRs.indexOf("];", bcRs.indexOf("pub const BYTEMOJIS")),
  );
  const rsEmojis = [...rsBlock.matchAll(/"([^"]+)"/g)].map((m) => req(m[1], "emoji literal"));
  expect(rsEmojis.length === 256, `bc-ur-rust BYTEMOJIS: got ${rsEmojis.length}`);
  crossChecked(ref, [rsEmojis], "BCR-2024-008 vs bc-ur-rust BYTEMOJIS");
  return ref;
}

function identifiers(bwDoc: string, bytemojiDoc: string, bcRs: string): void {
  const words = docWordTable(bwDoc);
  const emojis = docBytemojis(bytemojiDoc, bcRs);
  const identifier = (digest: number[]): string =>
    digest.map((b) => req(words[b], `word ${b}`)).join(" ");
  const bytemoji = (digest: number[]): string =>
    digest.map((b) => req(emojis[b], `emoji ${b}`)).join(" ");

  // BCR-2024-008 OIB example prints the same digest three ways.
  const oib = codeBlockContaining(bytemojiDoc, "JUGS DELI GIFT WHEN");
  const oibHex = req(/^([0-9a-f]{2} ){3}[0-9a-f]{2}$/im.exec(oib)?.[0], "OIB hex line").replaceAll(
    " ",
    "",
  );
  const oibWords = req(/([A-Z]{4} ){3}[A-Z]{4}/.exec(oib)?.[0], "OIB bytewords line");
  const oibEmojiLine = req(
    oib
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l.length > 0 && !/^[0-9a-f* ]+$/i.test(l) && !/[a-z]/.test(l)),
    "OIB bytemoji line",
  );
  const oibDigest = [...oibHex.matchAll(/[0-9a-f]{2}/g)].map((m) => Number.parseInt(m[0], 16));
  crossChecked(
    identifier(oibDigest),
    [oibWords.toLowerCase()],
    "BCR-2024-008 OIB bytewords vs doc table",
  );
  crossChecked(oibEmojiLine, [bytemoji(oibDigest)], "BCR-2024-008 OIB bytemoji vs doc table");

  // bc-ur-rust test literals anchor the bytewords form independently.
  const rs0123 = req(
    /encode_to_words\(&\[0, 1, 2, 3\]\),\s*"([^"]+)"/.exec(bcRs)?.[1],
    "bc-ur-rust identifier literal",
  );
  crossChecked(identifier([0, 1, 2, 3]), [rs0123], "identifier 0,1,2,3 vs bc-ur-rust");

  writeVector(
    "official/bytewords-identifier.json",
    "bytewords.identifier",
    researchSource("BCR-2024-008 + BCR-2020-012", "papers/bcr-2024-008-bytemoji.md", [
      "papers/bcr-2020-012-bytewords.md",
      BCUR_RS_BYTEWORDS,
    ]),
    [
      { name: "word table", words },
      { name: "bcr-2024-008 OIB", digestHex: oibHex, identifier: identifier(oibDigest) },
      { name: "bc-ur-rust 0,1,2,3", digestHex: "00010203", identifier: rs0123 },
      { name: "zero digest", digestHex: "00000000", identifier: identifier([0, 0, 0, 0]) },
      { name: "max digest", digestHex: "ffffffff", identifier: identifier([255, 255, 255, 255]) },
    ],
  );

  writeVector(
    "official/bytemoji.json",
    "bytemoji.identifier",
    researchSource("BCR-2024-008", "papers/bcr-2024-008-bytemoji.md", [BCUR_RS_BYTEWORDS]),
    [
      { name: "reference string", table: refBlockJoin(emojis) },
      {
        name: "bcr-2024-008 OIB",
        digestHex: oibHex,
        bytemojis: oibEmojiLine,
        bytewords: identifier(oibDigest),
      },
      { name: "0,1,2,3", digestHex: "00010203", bytemojis: bytemoji([0, 1, 2, 3]) },
      { name: "zero digest", digestHex: "00000000", bytemojis: bytemoji([0, 0, 0, 0]) },
      { name: "max digest", digestHex: "ffffffff", bytemojis: bytemoji([255, 255, 255, 255]) },
    ],
  );
}

/** Concatenated emoji table exactly as BCR-2024-008 prints it. */
function refBlockJoin(emojis: string[]): string {
  return emojis.join("");
}

/* -------------------------------------------------------------------- */

const [
  murDoc,
  bwDoc,
  urDoc,
  urtDoc,
  hdkeyDoc,
  sskrDoc,
  bytemojiDoc,
  kitFountain,
  kitBw,
  kitUr,
  cpp,
  bcRs,
] = await Promise.all([
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2024-001-multipart-ur.md"),
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2020-012-bytewords.md"),
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2020-005-ur.md"),
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2020-006-urtypes.md"),
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2020-007-hdkey.md"),
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2020-011-sskr.md"),
  fetchRaw("BlockchainCommons/Research", RESEARCH_SHA, "papers/bcr-2024-008-bytemoji.md"),
  fetchRaw("BlockchainCommons/URKit", URKIT_SHA, "Tests/URKitTests/FountainCodesTests.swift"),
  fetchRaw("BlockchainCommons/URKit", URKIT_SHA, "Tests/URKitTests/BytewordsTests.swift"),
  fetchRaw("BlockchainCommons/URKit", URKIT_SHA, "Tests/URKitTests/URTests.swift"),
  fetchRaw("BlockchainCommons/bc-ur", BCUR_SHA, "test/test.cpp"),
  fetchRaw("BlockchainCommons/bc-ur-rust", BCUR_RS_SHA, "src/bytewords.rs"),
]);

const multipartTable = readFileSync(join(VECTORS, "ur-rs/multipart-20.txt"), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l.length > 0);

mur(murDoc, kitFountain, cpp);
bytewords(bwDoc, kitBw, cpp);
ur(kitUr, cpp, urDoc, multipartTable);
registry(urtDoc, hdkeyDoc, sskrDoc, urDoc);
identifiers(bwDoc, bytemojiDoc, bcRs);

console.log(`wrote ${written.length} vector files:`);
for (const w of written) {
  console.log(`  ${w}`);
}
console.log(`${log.length} cross-checks passed`);
