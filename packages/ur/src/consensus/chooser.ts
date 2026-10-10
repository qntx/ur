import { Sampler } from "./sampler.ts";
import { Xoshiro256 } from "./xoshiro.ts";

/**
 * Per-stream index generator (BCR-2024-001 §4 FragmentChooser): harmonic degree sampler built once,
 * partial remove-shuffle per sequence.
 */
export class FragmentChooser {
  readonly fragmentCount: number;
  readonly checksum: number;
  readonly #degrees: Sampler;

  constructor(fragmentCount: number, checksum: number) {
    this.fragmentCount = fragmentCount;
    this.checksum = checksum;
    const weights: number[] = [];
    for (let x = 1; x <= fragmentCount; x++) {
      weights.push(1 / x);
    }
    this.#degrees = new Sampler(weights);
  }

  /**
   * Fragment indexes mixed into sequence `sequence` (1-based), sorted ascending. Normative: simple
   * if sequence <= K; else degree + remove-shuffle.
   */
  choose(sequence: number): number[] {
    if (sequence <= this.fragmentCount) {
      return [sequence - 1];
    }
    const seed = new Uint8Array(8);
    seed[0] = (sequence >>> 24) & 0xff;
    seed[1] = (sequence >>> 16) & 0xff;
    seed[2] = (sequence >>> 8) & 0xff;
    seed[3] = sequence & 0xff;
    seed[4] = (this.checksum >>> 24) & 0xff;
    seed[5] = (this.checksum >>> 16) & 0xff;
    seed[6] = (this.checksum >>> 8) & 0xff;
    seed[7] = this.checksum & 0xff;
    const xoshiro = Xoshiro256.fromBytes(seed);
    const degree = this.#degrees.next(xoshiro) + 1;
    const indexes = Array.from({ length: this.fragmentCount }, (_, i) => i);
    return xoshiro.shuffled(indexes, degree).sort((a, b) => a - b);
  }
}
