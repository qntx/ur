import { checksum } from "../crc32.ts";
import { UrError, fail, failPoison } from "../error.ts";
import type { DecoderPoison } from "../error.ts";
import { mergeLimits } from "./limits.ts";
import type { DecoderLimits } from "./limits.ts";
import { Part } from "./part.ts";

function keyOf(indexes: number[]): string {
  return indexes.join(",");
}

function xorInto(target: Uint8Array, src: Uint8Array): void {
  if (target.length !== src.length) {
    fail("DecoderState");
  }
  for (const [i, a] of target.entries()) {
    const b = src[i];
    if (b === undefined) {
      fail("DecoderState");
    }
    target[i] = a ^ b;
  }
}

/** Fountain decoder with resource limits and fail-closed poison. */
export class FountainDecoder {
  private readonly decoded = new Map<number, Part>();
  private readonly received = new Set<string>();
  private readonly buffer = new Map<string, { indexes: number[]; part: Part }>();
  private readonly queue: Array<{ index: number; part: Part }> = [];
  private sequenceCount = 0;
  private messageLength = 0;
  private messageChecksum = 0;
  private fragmentLength = 0;
  private readonly limits: DecoderLimits;
  private poisoned: DecoderPoison | undefined;

  constructor(limits?: Partial<DecoderLimits>) {
    this.limits = mergeLimits(limits);
  }

  get maxFragmentDataLength(): number {
    return this.limits.maxFragmentDataLength;
  }

  get maxFragmentCount(): number {
    return this.limits.maxFragmentCount;
  }

  get isPoisoned(): boolean {
    return this.poisoned !== undefined;
  }

  get poisonState(): DecoderPoison | undefined {
    return this.poisoned;
  }

  private poison(limit: string): never {
    this.poisoned = { code: "ResourceLimit", limit };
    fail("ResourceLimit", { limit });
  }

  private escalate(e: unknown): never {
    if (e instanceof UrError) {
      if (e.code === "ResourceLimit") {
        this.poisoned ??= { code: "ResourceLimit", limit: e.limit ?? "unknown" };
      } else if (e.code === "DecoderState") {
        this.poisoned ??= { code: "DecoderState" };
      }
    }
    throw e;
  }

  /**
   * Receive a fountain part.
   *
   * @returns Whether the part was newly ingested.
   */
  receive(part: Part): boolean {
    if (this.poisoned) {
      failPoison(this.poisoned);
    }
    if (this.complete) {
      return false;
    }

    if (part.sequenceCount === 0 || part.data.length === 0 || part.messageLength === 0) {
      fail("EmptyPart");
    }
    if (part.sequence === 0) {
      fail("InvalidSequence");
    }
    if (part.data.length > this.limits.maxFragmentDataLength) {
      this.poison("fragment_data");
    }

    if (this.received.size === 0) {
      const sc = part.sequenceCount;
      const ml = part.messageLength;
      if (sc > this.limits.maxFragmentCount) {
        this.poison("fragment_count");
      }
      if (ml > this.limits.maxMessageLength) {
        this.poison("message_length");
      }
      const fragLen = part.data.length;
      const product = fragLen * sc;
      if (!Number.isSafeInteger(product) || product > 0xff_ff_ff_ff) {
        this.poison("message_length");
      }
      // partition pads with at most fragLen - 1 bytes
      if (product < ml || product - ml >= fragLen) {
        fail("InconsistentPart");
      }
      this.sequenceCount = sc;
      this.messageLength = ml;
      this.messageChecksum = part.checksum;
      this.fragmentLength = fragLen;
    } else if (!this.validate(part)) {
      fail("InconsistentPart");
    }

    const indexes = part.indexes();
    const key = keyOf(indexes);
    if (this.received.has(key)) {
      return false;
    }
    if (this.received.size >= this.limits.maxReceivedParts) {
      this.poison("received_parts");
    }
    this.received.add(key);

    try {
      if (part.isSimple()) {
        this.enqueueSimple(part);
      } else {
        this.processComplex(part);
      }
      this.processQueue();
    } catch (error) {
      this.escalate(error);
    }
    return true;
  }

  private enqueueSimple(part: Part): void {
    const [index] = part.indexes();
    if (index === undefined) {
      fail("DecoderState");
    }
    if (this.decoded.has(index)) {
      return;
    }
    this.decoded.set(index, part);
    this.queue.push({ index, part });
  }

  private processQueue(): void {
    while (this.queue.length > 0) {
      const item = this.queue.pop();
      if (item === undefined) {
        fail("DecoderState");
      }
      const { index, part: simple } = item;
      const toProcess: string[] = [];
      for (const [k, entry] of this.buffer) {
        if (entry.indexes.includes(index)) {
          toProcess.push(k);
        }
      }
      for (const k of toProcess) {
        this.reduceBufferedPart(k, index, simple);
      }
    }
  }

  private reduceBufferedPart(key: string, knownIndex: number, simple: Part): void {
    const entry = this.buffer.get(key);
    if (!entry) {
      fail("DecoderState");
    }
    this.buffer.delete(key);
    const newIndexes = entry.indexes.filter((x) => x !== knownIndex);
    if (newIndexes.length === entry.indexes.length) {
      fail("DecoderState");
    }
    const data = new Uint8Array(entry.part.data);
    xorInto(data, simple.data);
    const reduced = Part.fromFields(
      entry.part.sequence,
      entry.part.sequenceCount,
      entry.part.messageLength,
      entry.part.checksum,
      data,
    );
    this.insertReduced(newIndexes, reduced);
  }

  private processComplex(part: Part): void {
    let indexes = [...part.indexes()];
    const known = indexes.filter((idx) => this.decoded.has(idx));
    if (indexes.length === known.length) {
      return;
    }
    const data = new Uint8Array(part.data);
    for (const remove of known) {
      indexes = indexes.filter((x) => x !== remove);
      const decoded = this.decoded.get(remove);
      if (decoded === undefined) {
        fail("DecoderState");
      }
      xorInto(data, decoded.data);
    }
    const reduced = Part.fromFields(
      part.sequence,
      part.sequenceCount,
      part.messageLength,
      part.checksum,
      data,
    );
    this.insertReduced(indexes, reduced);
  }

  private insertReduced(indexes: number[], part: Part): void {
    if (indexes.length === 1) {
      const [idx] = indexes;
      if (idx === undefined) {
        fail("DecoderState");
      }
      if (this.decoded.has(idx)) {
        return;
      }
      this.decoded.set(idx, part);
      this.queue.push({ index: idx, part });
      return;
    }
    const key = keyOf(indexes);
    if (!this.buffer.has(key) && this.buffer.size >= this.limits.maxBufferParts) {
      this.poison("buffer_parts");
    }
    this.buffer.set(key, { indexes, part });
  }

  get complete(): boolean {
    return this.messageLength !== 0 && this.decoded.size === this.sequenceCount;
  }

  resolvedFragmentCount(): number | undefined {
    return this.messageLength === 0 ? undefined : this.decoded.size;
  }

  get fragmentCount(): number {
    return this.sequenceCount;
  }

  validate(part: Part): boolean {
    if (this.received.size === 0) {
      return false;
    }
    return (
      part.sequenceCount === this.sequenceCount &&
      part.messageLength === this.messageLength &&
      part.checksum === this.messageChecksum &&
      part.data.length === this.fragmentLength
    );
  }

  /** Decoded message if complete; otherwise `undefined`. */
  message(): Uint8Array | undefined {
    if (this.poisoned) {
      failPoison(this.poisoned);
    }
    if (!this.complete) {
      return undefined;
    }
    const combined = new Uint8Array(this.fragmentLength * this.sequenceCount);
    for (let idx = 0; idx < this.sequenceCount; idx++) {
      const part = this.decoded.get(idx);
      if (!part) {
        fail("DecoderState");
      }
      combined.set(part.data, idx * this.fragmentLength);
    }
    for (let i = this.messageLength; i < combined.length; i++) {
      if (combined[i] !== 0) {
        fail("InvalidPadding");
      }
    }
    const message = combined.subarray(0, this.messageLength);
    if (checksum(message) !== this.messageChecksum) {
      fail("InvalidMessageChecksum");
    }
    return new Uint8Array(message);
  }
}
