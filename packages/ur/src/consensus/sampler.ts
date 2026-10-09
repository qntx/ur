import type { Xoshiro256 } from "./xoshiro.ts";

// Indices into weights/probs/aliases are always in range by construction.
function at(list: ReadonlyArray<number>, i: number): number {
  const v = list[i];
  if (v === undefined) {
    throw new Error("unreachable: index out of range");
  }
  return v;
}

/** Walker's alias method with reverse-index ordered partition (ur-rs / bcur). */
export class Sampler {
  private readonly aliases: number[];
  private readonly probs: number[];

  private constructor(aliases: number[], probs: number[]) {
    this.aliases = aliases;
    this.probs = probs;
  }

  static new(weightsIn: number[]): Sampler {
    const weights = [...weightsIn];
    for (const w of weights) {
      if (w < 0) {
        throw new Error("negative probability encountered");
      }
    }
    const summed = weights.reduce((a, b) => a + b, 0);
    if (!(summed > 0)) {
      throw new Error("probabilities don't sum to a positive value");
    }
    const count = weights.length;
    for (const [i, w] of weights.entries()) {
      weights[i] = w * (count / summed);
    }

    // Ordered partition: indices count-1 .. 0, small then large.
    const s: number[] = [];
    const l: number[] = [];
    for (let j = count - 1; j >= 0; j--) {
      if (at(weights, j) < 1) {
        s.push(j);
      } else {
        l.push(j);
      }
    }

    const probs = Array.from({ length: count }, () => 0);
    const aliases = Array.from({ length: count }, () => 0);

    while (s.length > 0 && l.length > 0) {
      const a = s.pop();
      const g = l.pop();
      if (a === undefined || g === undefined) {
        break;
      }
      probs[a] = at(weights, a);
      aliases[a] = g;
      // Evaluation order matches ur-rs `weights[g] += weights[a] - 1.0`; floats are not associative.
      weights[g] = at(weights, g) + (at(weights, a) - 1);
      if (at(weights, g) < 1) {
        s.push(g);
      } else {
        l.push(g);
      }
    }
    for (const i of l) {
      probs[i] = 1;
    }
    for (const i of s) {
      probs[i] = 1;
    }

    return new Sampler(aliases, probs);
  }

  next(xoshiro: Xoshiro256): number {
    const n = this.probs.length;
    // `nextInt` handles the `r1 == 1.0` edge by clamping to `n - 1` (same deviation as `nextInt`).
    const i = xoshiro.nextInt(0, n - 1);
    const r2 = xoshiro.nextDouble();
    if (r2 < at(this.probs, i)) {
      return i;
    }
    return at(this.aliases, i);
  }
}
