import { expect, test } from "vite-plus/test";

import { Weighted } from "../src/rng/sampler.ts";
import { Xoshiro256 } from "../src/rng/xoshiro.ts";

test("rng_1", () => {
  const rng = Xoshiro256.fromString("Wolf");
  const expected = [
    42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74, 40, 48, 77, 54, 88, 7, 5, 88, 37, 25, 82, 13, 69,
    59, 30, 39, 11, 82, 19, 99, 45, 87, 30, 15, 32, 22, 89, 44, 92, 77, 29, 78, 4, 92, 44, 68, 92,
    69, 1, 42, 89, 50, 37, 84, 63, 34, 32, 3, 17, 62, 40, 98, 82, 89, 24, 43, 85, 39, 15, 3, 99, 29,
    20, 42, 27, 10, 85, 66, 50, 35, 69, 70, 70, 74, 30, 13, 72, 54, 11, 5, 70, 55, 91, 52, 10, 43,
    43, 52,
  ];
  for (const e of expected) {
    expect(Number(rng.nextU64() % 100n)).toBe(e);
  }
});

test("rng_2_from_crc", () => {
  const rng = Xoshiro256.fromCrc(new TextEncoder().encode("Wolf"));
  const expected = [
    88, 44, 94, 74, 0, 99, 7, 77, 68, 35, 47, 78, 19, 21, 50, 15, 42, 36, 91, 11, 85, 39, 64, 22,
    57, 11, 25, 12, 1, 91, 17, 75, 29, 47, 88, 11, 68, 58, 27, 65, 21, 54, 47, 54, 73, 83, 23, 58,
    75, 27, 26, 15, 60, 36, 30, 21, 55, 57, 77, 76, 75, 47, 53, 76, 9, 91, 14, 69, 3, 95, 11, 73,
    20, 99, 68, 61, 3, 98, 36, 98, 56, 65, 14, 80, 74, 57, 63, 68, 51, 56, 24, 39, 53, 80, 57, 51,
    81, 3, 1, 30,
  ];
  for (const e of expected) {
    expect(Number(rng.nextU64() % 100n)).toBe(e);
  }
});

test("rng_3 next_int", () => {
  const rng = Xoshiro256.fromString("Wolf");
  const expected = [
    6, 5, 8, 4, 10, 5, 7, 10, 4, 9, 10, 9, 7, 7, 1, 1, 2, 9, 9, 2, 6, 4, 5, 7, 8, 5, 4, 2, 3, 8, 7,
    4, 5, 1, 10, 9, 3, 10, 2, 6, 8, 5, 7, 9, 3, 1, 5, 2, 7, 1, 4, 4, 4, 4, 9, 4, 5, 5, 6, 9, 5, 1,
    2, 8, 3, 3, 2, 8, 4, 3, 2, 1, 10, 8, 9, 3, 10, 8, 5, 5, 6, 7, 10, 5, 8, 9, 4, 6, 4, 2, 10, 2, 1,
    7, 9, 6, 7, 4, 2, 5,
  ];
  for (const e of expected) {
    expect(rng.nextInt(1, 10)).toBe(e);
  }
});

test("shuffle", () => {
  const rng = Xoshiro256.fromString("Wolf");
  const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  const expected = [
    [6, 4, 9, 3, 10, 5, 7, 8, 1, 2],
    [10, 8, 6, 5, 1, 2, 3, 9, 7, 4],
    [6, 4, 5, 8, 9, 3, 2, 1, 7, 10],
  ];
  for (const e of expected) {
    expect(rng.shuffled(values)).toStrictEqual(e);
  }
});

test("sampler", () => {
  const weights = [1, 2, 4, 8];
  const xoshiro = Xoshiro256.fromString("Wolf");
  const sampler = Weighted.new(weights);
  const expected = [
    3, 3, 3, 3, 3, 3, 3, 0, 2, 3, 3, 3, 3, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1, 1, 2, 1, 1, 3, 1, 3,
  ];
  for (const e of expected) {
    expect(sampler.next(xoshiro)).toBe(e);
  }
});

test("unit_interval excludes one", () => {
  // unit_interval(u64::MAX) < 1.0
  const max = (1n << 64n) - 1n;
  const SCALE = 1 / 2 ** 53;
  const u = Number(max >> 11n) * SCALE;
  expect(u).toBeLessThan(1);
});
