import {
  bytesToHex,
  decodeCbor,
  encodeCbor,
  hexToBytes,
  taggedValue,
} from "@blockchaincommons/dcbor";
import { expect, test } from "vite-plus/test";

import { UrError } from "../../src/error.ts";
import {
  TAGS,
  accountDescriptorCodec,
  addressCodec,
  ecKeyCodec,
  outputDescriptorCodec,
} from "../../src/registry/index.ts";
import type { EcKey } from "../../src/registry/index.ts";

const PUB = hexToBytes(`02${"ab".repeat(32)}`);
const PRIV = hexToBytes("01".repeat(32));
const ADDR = hexToBytes("77bff20c60e522dfaa3350c39b030a5d004e839a");

function errorCode(fn: () => void): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof UrError) {
      return error.code;
    }
    if (error instanceof Error && "code" in error) {
      return String((error as { code: unknown }).code);
    }
    throw error;
  }
  throw new Error("expected throw");
}

test("eckey encode validates like decode", () => {
  expect(ecKeyCodec.encode({ data: PUB })).toStrictEqual(
    ecKeyCodec.encode({ data: Uint8Array.from(PUB) }),
  );
  expect(bytesToHex(encodeCbor(ecKeyCodec.encode({ data: PRIV, isPrivate: true })))).toBe(
    `a202f5035820${"01".repeat(32)}`,
  );
  // Defaults are omitted on write.
  expect(bytesToHex(encodeCbor(ecKeyCodec.encode({ data: PUB })))).toBe(
    `a103582102${"ab".repeat(32)}`,
  );
  expect(bytesToHex(encodeCbor(ecKeyCodec.encode({ data: PUB, curve: 0, isPrivate: false })))).toBe(
    `a103582102${"ab".repeat(32)}`,
  );
  expect(errorCode(() => ecKeyCodec.encode({ data: PUB, isPrivate: true }))).toBe("OutOfRange");
  expect(errorCode(() => ecKeyCodec.encode({ data: PRIV, isPrivate: false }))).toBe("OutOfRange");
  expect(errorCode(() => ecKeyCodec.encode({ curve: 1, data: new Uint8Array() }))).toBe(
    "OutOfRange",
  );
  const other = ecKeyCodec.encode({ curve: 1, data: new Uint8Array(4) });
  const decoded = ecKeyCodec.decode(other);
  expect(decoded.curve).toBe(1);
});

test("eckey decode copies data (ownership)", () => {
  const key: EcKey = { data: PUB };
  const decoded = ecKeyCodec.decode(ecKeyCodec.encode(key));
  decoded.data[0] = 0;
  expect(PUB[0]).toBe(2);
});

test("address codec type mapping and defaults", () => {
  const bare = addressCodec.decode(decodeCbor(hexToBytes(`a10354${bytesToHex(ADDR)}`)));
  expect(bare.type).toBeUndefined();
  expect(bytesToHex(encodeCbor(addressCodec.encode(bare)))).toBe(`a10354${bytesToHex(ADDR)}`);

  const typed = addressCodec.decode(decodeCbor(hexToBytes(`a202020354${bytesToHex(ADDR)}`)));
  expect(typed.type).toBe("p2wpkh");
  expect(errorCode(() => addressCodec.encode({ type: "p2pkh", data: new Uint8Array(19) }))).toBe(
    "OutOfRange",
  );
  expect(errorCode(() => addressCodec.encode({ data: new Uint8Array() }))).toBe("OutOfRange");
});

test("output-descriptor placeholder validation on encode", () => {
  const keys = [{ kind: "eckey" as const, key: { data: PUB } }];
  expect(errorCode(() => outputDescriptorCodec.encode({ source: "pk(@1)", keys }))).toBe(
    "OutOfRange",
  );
  expect(errorCode(() => outputDescriptorCodec.encode({ source: "pkh(x)", keys }))).toBe(
    "OutOfRange",
  );
  // No placeholders and no keys: key 2 omitted.
  const raw = outputDescriptorCodec.encode({ source: "raw(deadbeef)", keys: [] });
  expect(bytesToHex(encodeCbor(raw))).toBe("a1016d72617728646561646265656629");
});

test("output-descriptor embedded keys accept v1 and v2 tags", () => {
  const ecV1 = taggedValue(
    TAGS["crypto-eckey"],
    decodeCbor(hexToBytes(`a103582102${"ab".repeat(32)}`)),
  );
  const ecV2 = taggedValue(TAGS.eckey, decodeCbor(hexToBytes(`a103582102${"ab".repeat(32)}`)));
  for (const tagged of [ecV1, ecV2]) {
    const body = decodeCbor(
      hexToBytes(`a20167706b68284030290281${bytesToHex(encodeCbor(tagged))}`),
    );
    const value = outputDescriptorCodec.decode(body);
    expect(value.source).toBe("pkh(@0)");
    expect(value.keys[0]?.kind).toBe("eckey");
  }
});

test("account-descriptor encode validation", () => {
  const desc = {
    source: "pkh(@0)",
    keys: [{ kind: "eckey" as const, key: { data: PUB } }],
  };
  const account = { masterFingerprint: 0x37b5eed4, outputDescriptors: [desc] };
  const round = accountDescriptorCodec.decode(accountDescriptorCodec.encode(account));
  expect(round.masterFingerprint).toBe(0x37b5eed4);
  expect(round.outputDescriptors[0]?.source).toBe("pkh(@0)");
  expect(
    errorCode(() =>
      accountDescriptorCodec.encode({
        masterFingerprint: 0x1_00_00_00_00,
        outputDescriptors: [desc],
      }),
    ),
  ).toBe("OutOfRange");
  expect(
    errorCode(() => accountDescriptorCodec.encode({ masterFingerprint: 1, outputDescriptors: [] })),
  ).toBe("OutOfRange");
});
