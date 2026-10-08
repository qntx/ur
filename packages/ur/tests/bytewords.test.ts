import { expect, test } from "vite-plus/test";

import { canonicalizeByteword, decode, encode, encodeRaw } from "../src/bytewords/index.ts";
import { UrError } from "../src/error.ts";
import { vectorJson } from "./vectors.ts";

const BYTEWORDS = vectorJson<{ inputHex: string; standard: string; uri: string; minimal: string }>(
  "bytewords/contract.json",
);

test("bytewords styles and roundtrip", () => {
  const input = new Uint8Array(Buffer.from(BYTEWORDS.inputHex, "hex"));
  expect(encode(input, "standard")).toBe(BYTEWORDS.standard);
  expect(encode(input, "uri")).toBe(BYTEWORDS.uri);
  expect(encode(input, "minimal")).toBe(BYTEWORDS.minimal);

  expect(decode(BYTEWORDS.standard, "standard")).toStrictEqual(input);
  expect(decode(BYTEWORDS.uri, "uri")).toStrictEqual(input);
  expect(decode(BYTEWORDS.minimal, "minimal")).toStrictEqual(input);

  expect(decode(encode(new Uint8Array(), "minimal"), "minimal")).toStrictEqual(new Uint8Array());
});

test("bytewords errors", () => {
  expect(() => decode("able acid also lava zero jade need echo wolf", "standard")).toThrow(UrError);
  expect(() => decode("able acid also lava zero jade need echo wolf", "standard")).toThrow(
    "invalid bytewords checksum",
  );
  expect(() => decode("axxe tied also webs lung", "standard")).toThrow(UrError);
  expect(() => decode("aea", "minimal")).toThrow(UrError);
  expect(() => decode("₿", "standard")).toThrow(UrError);
});

test("single zero minimal", () => {
  expect(encode(new Uint8Array([0]), "minimal")).toBe("aetdaowslg");
  expect(decode("aetdaowslg", "minimal")).toStrictEqual(new Uint8Array([0]));
});

test("case insensitive decode", () => {
  const input = new Uint8Array([0, 1, 2]);
  const standard = encode(input, "standard");
  const minimal = encode(input, "minimal");
  expect(decode(standard.toUpperCase(), "standard")).toStrictEqual(input);
  expect(decode(minimal.toUpperCase(), "minimal")).toStrictEqual(input);
});

test("encodeRaw and canonicalize", () => {
  expect(encodeRaw(new Uint8Array([0]), "minimal")).toBe("ae");
  expect(canonicalizeByteword("ABLE")).toBe("able");
  expect(canonicalizeByteword("ae")).toBe("able");
  expect(canonicalizeByteword("abl")).toBe("able");
  expect(canonicalizeByteword("ble")).toBe("able");
  expect(canonicalizeByteword("nope")).toBeUndefined();
  expect(canonicalizeByteword("a")).toBeUndefined();
});

test("long vector", () => {
  const input = Uint8Array.from([
    245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212, 19, 159,
    17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242, 254, 147, 204,
    66, 163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184, 197, 33, 113, 88, 14, 157,
    31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144, 65, 240, 133, 69, 113, 247, 63, 53,
    242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82, 69, 254, 165, 138, 41, 85, 24,
  ]);
  const encoded =
    "yank toys bulb skew when warm free fair tent swan open brag mint noon jury list view tiny brew note body data webs what zinc bald join runs data whiz days keys user diet news ruby whiz zone menu surf flew omit trip pose runs fund part even crux fern math visa tied loud redo silk curl jugs hard beta next cost puma drum acid junk swan free very mint flap warm fact math flap what limp free jugs yell fish epic whiz open numb math city belt glow wave limp fuel grim free zone open love diet gyro cats fizz holy city puff";
  const encodedMinimal =
    "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwnebydawswtzcbdjnrsdawzdsksurdtnsrywzzemusffwottppersfdptencxfnmhvatdldroskcljshdbantctpadmadjksnfevymtfpwmftmhfpwtlpfejsylfhecwzonnbmhcybtgwwelpflgmfezeonledtgocsfzhycypf";
  expect(decode(encoded, "standard")).toStrictEqual(input);
  expect(decode(encodedMinimal, "minimal")).toStrictEqual(input);
  expect(encode(input, "standard")).toBe(encoded);
  expect(encode(input, "minimal")).toBe(encodedMinimal);
});
