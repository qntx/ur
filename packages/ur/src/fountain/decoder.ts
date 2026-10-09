import { FragmentChooser } from "../consensus/chooser.ts";
import { checksum } from "../consensus/crc32.ts";
import { UrError } from "../error.ts";
import type { UrErrorInfo } from "../error.ts";
import { mergeLimits } from "./limits.ts";
import type { DecoderLimits } from "./limits.ts";
import type { Part } from "./part.ts";
import { validatePart } from "./part.ts";

/**
 * Per-frame outcome of {@link FountainDecoder.receive}: `accepted` raised the rank, `duplicate`
 * added nothing (including any frame in a terminal state), `rejected` left the session unchanged,
 * and `fatal` moved it to `failed`.
 */
export type ReceiveResult =
  | Readonly<{ status: "accepted" | "duplicate" }>
  | Readonly<{ status: "rejected" | "fatal"; error: UrError }>;

/** Decoder state machine snapshot. */
export type DecoderState<T> =
  | Readonly<{ phase: "empty" }>
  | Readonly<{ phase: "collecting"; progress: Progress }>
  | Readonly<{ phase: "complete"; value: T }>
  | Readonly<{ phase: "failed"; error: UrError }>;

/** Progress snapshot; `ratio` is the exact GF(2) rank fraction. */
export type Progress = Readonly<{
  /** `K`; `0` while empty. */
  fragmentCount: number;
  /** Linearly independent parts received. */
  rank: number;
  /** Rows reduced to a single column — recovered source fragments. */
  recovered: number;
  /** Frames that were `accepted` or `duplicate`. */
  processed: number;
  /** `rank / K`; exactly `1` when complete, `0` when empty. */
  ratio: number;
}>;

/** One retained fountain row in reduced row-echelon form. */
type Row = {
  /** `K`-bit set of columns XORed into this row. */
  mask: Uint32Array;
  /** Row payload; the backing buffer is padded to a multiple of 4 bytes. */
  data: Uint32Array;
  /** Cached `popcount(mask)`. */
  ones: number;
};

function maskBit(mask: Uint32Array, column: number): boolean {
  return ((mask[column >>> 5] ?? 0) & (1 << (column & 31))) !== 0;
}

function maskSet(mask: Uint32Array, column: number): void {
  const word = column >>> 5;
  mask[word] = (mask[word] ?? 0) | (1 << (column & 31));
}

function maskLowestBit(mask: Uint32Array): number | undefined {
  for (let i = 0; i < mask.length; i += 1) {
    const word = mask[i] ?? 0;
    if (word !== 0) {
      return i * 32 + (31 - Math.clz32(word & -word));
    }
  }
  return undefined;
}

/** SWAR population count; ~5 ops per word vs a per-set-bit loop. */
function popcount32(value: number): number {
  let w = value;
  w -= (w >>> 1) & 0x55_55_55_55;
  w = (w & 0x33_33_33_33) + ((w >>> 2) & 0x33_33_33_33);
  w = (w + (w >>> 4)) & 0x0f_0f_0f_0f;
  return (w * 0x01_01_01_01) >>> 24;
}

function maskPopcount(mask: Uint32Array): number {
  let ones = 0;
  for (const word of mask) {
    ones += popcount32(word);
  }
  return ones;
}

function xorWords(target: Uint32Array, source: Uint32Array): void {
  for (let i = 0; i < target.length; i += 1) {
    target[i] = (target[i] ?? 0) ^ (source[i] ?? 0);
  }
}

function toUrError(error: unknown): UrError {
  return error instanceof UrError ? error : new UrError({ code: "Internal" });
}

/**
 * Incremental Gauss-Jordan fountain decoder over GF(2).
 *
 * Rows are stored in reduced row echelon form keyed by pivot column, at most `K` rows. `receive`
 * never throws for frame problems: outcomes are reported as {@link ReceiveResult}. A fatal result
 * moves the session to `failed`; every further frame is then a `duplicate`.
 */
/** Stream metadata fixed by the first consistent part. */
type LockedStream = {
  chooser: FragmentChooser;
  sequenceCount: number;
  messageLength: number;
  checksum: number;
  fragmentLength: number;
};

/** Session phase; `complete`/`failed` carry their payload so the `state` getter needs no guards. */
type Session =
  | { phase: "empty" }
  | { phase: "collecting" }
  | { phase: "complete"; value: Uint8Array }
  | { phase: "failed"; error: UrError };

export class FountainDecoder {
  readonly #limits: DecoderLimits;
  #session: Session = { phase: "empty" };
  #stream: LockedStream | undefined;
  /** `rows[p]` is the row whose pivot is column `p`. */
  #rows: Array<Row | undefined> = [];
  #rank = 0;
  #recovered = 0;
  #processed = 0;
  #lastIndexes: ReadonlyArray<number> = [];

  constructor(options?: Readonly<{ limits?: Partial<DecoderLimits> }>) {
    this.#limits = mergeLimits(options?.limits);
  }

  /**
   * Receive a fountain part. `accepted`/`duplicate` increment `processed`; `rejected` leaves the
   * session unchanged; `fatal` enters `failed`.
   */
  receive(part: Part): ReceiveResult {
    if (this.#session.phase === "complete" || this.#session.phase === "failed") {
      this.#processed += 1;
      return { status: "duplicate" };
    }
    try {
      validatePart(part);
    } catch (error) {
      return { status: "rejected", error: toUrError(error) };
    }
    if (part.data.length > this.#limits.maxFragmentLength) {
      return this.#fail({ code: "ResourceLimit", limit: "fragmentLength" });
    }
    const locked = this.#lockStream(part);
    if ("result" in locked) {
      return locked.result;
    }
    const { stream } = locked;
    const indexes = stream.chooser.choose(part.sequence);
    const accepted = this.#insertRow(stream, indexes, part.data);
    this.#lastIndexes = indexes;
    this.#processed += 1;
    if (!accepted) {
      return { status: "duplicate" };
    }
    if (this.#rank === stream.sequenceCount) {
      const failure = this.#join(stream);
      if (failure !== undefined) {
        return failure;
      }
    }
    return { status: "accepted" };
  }

  /**
   * Returns the locked stream metadata. The first part fixes `K`, `messageLength`, `checksum`, and
   * `fragmentLength` (limit violations are fatal); later parts must match (`InconsistentPart`).
   */
  #lockStream(part: Part): { stream: LockedStream } | { result: ReceiveResult } {
    const stream = this.#stream;
    if (stream !== undefined) {
      if (
        part.sequenceCount !== stream.sequenceCount ||
        part.messageLength !== stream.messageLength ||
        part.checksum !== stream.checksum ||
        part.data.length !== stream.fragmentLength
      ) {
        return {
          result: { status: "rejected", error: new UrError({ code: "InconsistentPart" }) },
        };
      }
      return { stream };
    }
    if (part.sequenceCount > this.#limits.maxFragmentCount) {
      return { result: this.#fail({ code: "ResourceLimit", limit: "fragmentCount" }) };
    }
    if (part.messageLength > this.#limits.maxMessageLength) {
      return { result: this.#fail({ code: "ResourceLimit", limit: "messageLength" }) };
    }
    const created: LockedStream = {
      chooser: new FragmentChooser(part.sequenceCount, part.checksum),
      sequenceCount: part.sequenceCount,
      messageLength: part.messageLength,
      checksum: part.checksum,
      fragmentLength: part.data.length,
    };
    this.#stream = created;
    this.#rows = Array.from({ length: part.sequenceCount }, (): Row | undefined => undefined);
    this.#session = { phase: "collecting" };
    return { stream: created };
  }

  /**
   * Forward-eliminates the part against existing pivot rows, then back-substitutes the new row into
   * every row sharing its pivot column. Returns whether the rank increased.
   */
  #insertRow(stream: LockedStream, indexes: ReadonlyArray<number>, data: Uint8Array): boolean {
    const mask = new Uint32Array(Math.ceil(stream.sequenceCount / 32));
    for (const index of indexes) {
      maskSet(mask, index);
    }
    const rowData = new Uint32Array(Math.ceil(stream.fragmentLength / 4));
    new Uint8Array(rowData.buffer, rowData.byteOffset, stream.fragmentLength).set(data);

    // RREF: eliminating at an existing pivot can only set non-pivot bits, so
    // scanning the part's own index set covers every elimination.
    for (const index of indexes) {
      if (!maskBit(mask, index)) {
        continue;
      }
      const row = this.#rows[index];
      if (row === undefined) {
        continue;
      }
      xorWords(mask, row.mask);
      xorWords(rowData, row.data);
    }
    const pivot = maskLowestBit(mask);
    if (pivot === undefined) {
      return false;
    }
    for (const row of this.#rows) {
      if (row === undefined || !maskBit(row.mask, pivot)) {
        continue;
      }
      const wasUnit = row.ones === 1;
      xorWords(row.mask, mask);
      xorWords(row.data, rowData);
      row.ones = maskPopcount(row.mask);
      if (wasUnit && row.ones !== 1) {
        this.#recovered -= 1;
      } else if (!wasUnit && row.ones === 1) {
        this.#recovered += 1;
      }
    }
    const ones = maskPopcount(mask);
    if (ones === 1) {
      this.#recovered += 1;
    }
    this.#rows[pivot] = { mask, data: rowData, ones };
    this.#rank += 1;
    return true;
  }

  /**
   * Joins the `K` unit rows in fragment order and verifies padding and CRC-32 exactly once. Returns
   * a `fatal` result or `undefined` on success.
   */
  #join(stream: LockedStream): ReceiveResult | undefined {
    const combined = new Uint8Array(stream.fragmentLength * stream.sequenceCount);
    for (const [i, row] of this.#rows.entries()) {
      if (row === undefined || row.ones !== 1) {
        return this.#fail({ code: "Internal" });
      }
      const bytes = new Uint8Array(row.data.buffer, row.data.byteOffset, stream.fragmentLength);
      combined.set(bytes, i * stream.fragmentLength);
    }
    for (let i = stream.messageLength; i < combined.length; i++) {
      if (combined[i] !== 0) {
        return this.#fail({ code: "InvalidPadding" });
      }
    }
    const message = combined.subarray(0, stream.messageLength);
    if (checksum(message) !== stream.checksum) {
      return this.#fail({ code: "InvalidMessageChecksum" });
    }
    this.#session = { phase: "complete", value: message };
    return undefined;
  }

  /** Moves the session to `failed` and returns the fatal result. */
  #fail(info: UrErrorInfo): ReceiveResult {
    const error = new UrError(info);
    this.#session = { phase: "failed", error };
    return { status: "fatal", error };
  }

  /** Current session state. */
  get state(): DecoderState<Uint8Array> {
    const session = this.#session;
    switch (session.phase) {
      case "complete":
        return { phase: "complete", value: session.value };
      case "failed":
        return { phase: "failed", error: session.error };
      case "collecting":
        return { phase: "collecting", progress: this.progress };
      default:
        return { phase: "empty" };
    }
  }

  /** Progress snapshot (`empty` reports all zeros). */
  get progress(): Progress {
    const k = this.#stream?.sequenceCount ?? 0;
    return {
      fragmentCount: k,
      rank: this.#rank,
      recovered: this.#recovered,
      processed: this.#processed,
      ratio: k === 0 ? 0 : this.#rank / k,
    };
  }

  /** Fragment indexes of the most recent `accepted`/`duplicate` part. */
  get lastIndexes(): ReadonlyArray<number> {
    return this.#lastIndexes;
  }

  /** Returns the session to `empty`; limits are kept. */
  reset(): void {
    this.#session = { phase: "empty" };
    this.#stream = undefined;
    this.#rows = [];
    this.#rank = 0;
    this.#recovered = 0;
    this.#processed = 0;
    this.#lastIndexes = [];
  }
}
